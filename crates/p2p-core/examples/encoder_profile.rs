//! Profiling temporário: compara configurações do encoder H.264 com rolagem simulada (rodar com --release)
use openh264::encoder::{BitRate, Complexity, Encoder, EncoderConfig, FrameRate, IntraFramePeriod, RateControlMode, SpsPpsStrategy, UsageType};
use openh264::formats::{RgbaSliceU8, YUVBuffer};
use openh264::OpenH264API;
use std::time::Instant;
use xcap::Monitor;

fn downscale(raw: &[u8], w: usize, h: usize, tw: usize, th: usize) -> Vec<u8> {
    let mut out = vec![0u8; tw * th * 4];
    for y in 0..th {
        let src_row = (y * h / th) * w * 4;
        for x in 0..tw {
            let si = src_row + (x * w / tw) * 4;
            out[(y * tw + x) * 4..(y * tw + x) * 4 + 4].copy_from_slice(&raw[si..si + 4]);
        }
    }
    out
}

fn base() -> EncoderConfig {
    EncoderConfig::new()
        .max_frame_rate(FrameRate::from_hz(30.0))
        .sps_pps_strategy(SpsPpsStrategy::ConstantId)
        .intra_frame_period(IntraFramePeriod::from_num_frames(30))
        .skip_frames(false)
}

fn main() {
    let max_width: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1280);
    let monitor = Monitor::all().unwrap().into_iter().next().unwrap();
    let img = monitor.capture_image().unwrap();
    let (w, h) = (img.width() as usize, img.height() as usize);
    let tw = w.min(max_width) & !1;
    let th = ((h as f32 * (tw as f32 / w as f32)) as usize & !1).max(2);
    let src = if tw != w { downscale(&img.into_raw(), w, h, tw, th) } else { img.into_raw() };
    let noise = std::env::args().nth(2).as_deref() == Some("noise");
    let frames: Vec<Vec<u8>> = (0..60)
        .map(|i| {
            if noise {
                // Mesmo padrão da janela moving_window: todos os pixels mudam a cada frame
                let mut f = vec![255u8; tw * th * 4];
                for y in 0..th { for x in 0..tw {
                    let v = (x + i * 7) ^ (y + i * 3);
                    let o = (y * tw + x) * 4;
                    f[o] = (v & 0xff) as u8; f[o + 1] = ((v >> 2) & 0xff) as u8; f[o + 2] = ((x + y + i) & 0xff) as u8;
                }}
                f
            } else { let mut f = src.clone(); f.rotate_left((i * 12 % th) * tw * 4); f }
        })
        .collect();
    println!("Resolução {}x{}, 60 frames com rolagem de 12 linhas/frame\n", tw, th);

    let t = Instant::now();
    for f in &frames { let _ = std::hint::black_box(YUVBuffer::from_rgb_source(RgbaSliceU8::new(f, (tw, th)))); }
    let slow = t.elapsed().as_secs_f64() * 1e3 / frames.len() as f64;
    let t = Instant::now();
    for f in &frames { let _ = std::hint::black_box(YUVBuffer::from_rgba8_source(RgbaSliceU8::new(f, (tw, th)))); }
    let fast = t.elapsed().as_secs_f64() * 1e3 / frames.len() as f64;
    println!("RGBA->YUV: from_rgb_source {:.2} ms | from_rgba8_source {:.2} ms\n", slow, fast);

    let variants: Vec<(&str, EncoderConfig)> = vec![
        ("atual (Screen, RC Off, Medium)", base().usage_type(UsageType::ScreenContentRealTime).rate_control_mode(RateControlMode::Off)),
        ("Screen, RC Off, Low", base().usage_type(UsageType::ScreenContentRealTime).rate_control_mode(RateControlMode::Off).complexity(Complexity::Low)),
        ("Screen, Bitrate 3Mbps, Low", base().usage_type(UsageType::ScreenContentRealTime).rate_control_mode(RateControlMode::Bitrate).bitrate(BitRate::from_bps(3_000_000)).complexity(Complexity::Low)),
        ("Screen, Bitrate 3Mbps, Low, 4 threads", base().usage_type(UsageType::ScreenContentRealTime).rate_control_mode(RateControlMode::Bitrate).bitrate(BitRate::from_bps(3_000_000)).complexity(Complexity::Low).num_threads(4)),
        ("Camera, Bitrate 3Mbps, Low", base().usage_type(UsageType::CameraVideoRealTime).rate_control_mode(RateControlMode::Bitrate).bitrate(BitRate::from_bps(3_000_000)).complexity(Complexity::Low)),
        ("Camera, Bitrate 3Mbps, Low, 4 threads", base().usage_type(UsageType::CameraVideoRealTime).rate_control_mode(RateControlMode::Bitrate).bitrate(BitRate::from_bps(3_000_000)).complexity(Complexity::Low).num_threads(4)),
    ];

    for (name, cfg) in variants {
        let mut enc = Encoder::with_api_config(OpenH264API::from_source(), cfg).unwrap();
        let (mut yuv_ms, mut enc_ms, mut bytes, mut key_bytes) = (0.0, 0.0, 0usize, 0usize);
        for (i, f) in frames.iter().enumerate() {
            let t = Instant::now();
            let yuv = YUVBuffer::from_rgb_source(RgbaSliceU8::new(f, (tw, th)));
            yuv_ms += t.elapsed().as_secs_f64() * 1e3;
            let t = Instant::now();
            if i % 30 == 0 { enc.force_intra_frame(); }
            let out = enc.encode(&yuv).unwrap().to_vec();
            enc_ms += t.elapsed().as_secs_f64() * 1e3;
            if i % 30 == 0 { key_bytes += out.len() } else { bytes += out.len() }
        }
        let n = frames.len() as f64;
        let per_frame = (yuv_ms + enc_ms) / n;
        println!("{:<40} yuv {:>5.1} ms + enc {:>5.1} ms = {:>5.1} ms (teto {:>4.0} FPS) | P {:>5.1} KB | key {:>5.0} KB",
            name, yuv_ms / n, enc_ms / n, per_frame, 1000.0 / per_frame, bytes as f64 / 58.0 / 1024.0, key_bytes as f64 / 2.0 / 1024.0);
    }
}
