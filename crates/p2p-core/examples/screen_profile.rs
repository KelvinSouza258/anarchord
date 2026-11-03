//! Profiling temporário do pipeline de compartilhamento de tela (rodar com --release)
use openh264::decoder::Decoder;
use openh264::encoder::{Encoder, EncoderConfig, FrameRate, IntraFramePeriod, RateControlMode, SpsPpsStrategy, UsageType};
use openh264::formats::{RgbaSliceU8, YUVBuffer, YUVSource};
use openh264::{nal_units, OpenH264API};
use p2p_core::screen::{ScreenPacket, VideoCodec};
use std::time::{Duration, Instant};
use xcap::Monitor;

fn downscale(raw: &[u8], w: usize, h: usize, tw: usize, th: usize) -> Vec<u8> {
    let mut out = vec![0u8; tw * th * 4];
    for y in 0..th {
        let src_row = (y * h / th) * w * 4;
        let dst_row = y * tw * 4;
        for x in 0..tw {
            let si = src_row + (x * w / tw) * 4;
            let di = dst_row + x * 4;
            out[di..di + 4].copy_from_slice(&raw[si..si + 4]);
        }
    }
    out
}

struct Stat(&'static str, Vec<Duration>);
impl Stat {
    fn add(&mut self, d: Duration) { self.1.push(d); }
    fn print(&self) {
        let mut v = self.1.clone();
        v.sort();
        let avg = v.iter().sum::<Duration>() / v.len() as u32;
        println!("{:<38} média {:>7.2} ms | p50 {:>7.2} | max {:>7.2}", self.0,
            avg.as_secs_f64() * 1e3, v[v.len() / 2].as_secs_f64() * 1e3, v[v.len() - 1].as_secs_f64() * 1e3);
    }
}

fn main() {
    let max_width: usize = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(1280);
    let frames = 60;
    let motion = std::env::args().nth(2).as_deref() == Some("motion");
    let monitor = Monitor::all().unwrap().into_iter().next().expect("monitor");
    println!("Monitor: {}x{} | alvo largura {}", monitor.width().unwrap(), monitor.height().unwrap(), max_width);

    let config = EncoderConfig::new()
        .usage_type(UsageType::ScreenContentRealTime)
        .rate_control_mode(RateControlMode::Off)
        .skip_frames(false)
        .max_frame_rate(FrameRate::from_hz(30.0))
        .sps_pps_strategy(SpsPpsStrategy::ConstantId)
        .intra_frame_period(IntraFramePeriod::from_num_frames(30));
    let mut enc = Encoder::with_api_config(OpenH264API::from_source(), config).unwrap();
    let mut dec = Decoder::new().unwrap();

    let mut s_cap = Stat("1. xcap capture_image", vec![]);
    let mut s_ds = Stat("2. downscale (nearest)", vec![]);
    let mut s_yuv = Stat("3. RGBA -> YUV", vec![]);
    let mut s_enc = Stat("4. H.264 encode", vec![]);
    let mut s_ser = Stat("5. JSON serialize ScreenPacket", vec![]);
    let mut s_try = Stat("6. recv: 3 parses falhos (Chat/Voz/Arq)", vec![]);
    let mut s_de = Stat("7. recv: parse ScreenPacket", vec![]);
    let mut s_dec = Stat("8. H.264 decode", vec![]);
    let mut s_rgb = Stat("9. YUV -> RGBA -> u32 (janela)", vec![]);
    let (mut key_sizes, mut p_sizes, mut json_key, mut json_p) = (vec![], vec![], vec![], vec![]);
    let mut too_large = 0;
    let (mut tw, mut th) = (0, 0);

    for seq in 0..frames {
        let t = Instant::now();
        let img = monitor.capture_image().unwrap();
        s_cap.add(t.elapsed());
        let (w, h) = (img.width() as usize, img.height() as usize);
        let raw = img.into_raw();

        let t = Instant::now();
        tw = w.min(max_width) & !1;
        th = ((h as f32 * (tw as f32 / w as f32)) as usize & !1).max(2);
        let rgba = if tw != w { downscale(&raw, w, h, tw, th) } else { raw };
        s_ds.add(t.elapsed());
        // Simula rolagem de tela (movimento) deslocando as linhas a cada frame
        let mut rgba = rgba;
        if motion {
            let shift = (seq as usize * 12 % th) * tw * 4;
            rgba.rotate_left(shift);
        }

        let t = Instant::now();
        let yuv = YUVBuffer::from_rgb_source(RgbaSliceU8::new(&rgba, (tw, th)));
        s_yuv.add(t.elapsed());

        let key = seq % 30 == 0;
        let t = Instant::now();
        if key { enc.force_intra_frame(); }
        let bytes = enc.encode(&yuv).unwrap().to_vec();
        s_enc.add(t.elapsed());
        if key { key_sizes.push(bytes.len()) } else { p_sizes.push(bytes.len()) }

        let pkt = ScreenPacket {
            stream_id: "screen:abcdef12".into(), sender_pubkey: "a".repeat(64), sender_name: "Alice".into(),
            frame_seq: seq, width: tw as u32, height: th as u32, timestamp_ms: 0,
            codec: VideoCodec::H264, is_keyframe: key, video_data: bytes.clone(),
        };
        let t = Instant::now();
        let json = pkt.to_bytes();
        s_ser.add(t.elapsed());
        if key { json_key.push(json.len()) } else { json_p.push(json.len()) }
        if json.len() > 1024 * 1024 { too_large += 1; }

        let t = Instant::now();
        // O tipo vem no envelope: nada de tentar desserializar em sequência
        let _ = p2p_core::wire::decode(&json);
        s_try.add(t.elapsed());

        let t = Instant::now();
        let back = ScreenPacket::from_bytes(&json).unwrap();
        s_de.add(t.elapsed());

        let mut decode_time = Duration::ZERO;
        for nal in nal_units(&back.video_data) {
            let t = Instant::now();
            let decoded = dec.decode(nal);
            decode_time += t.elapsed();
            let Ok(Some(y)) = decoded else { continue };
            let t = Instant::now();
            let (dw, dh) = y.dimensions();
            let mut staging = vec![0u8; dw * dh * 4];
            y.write_rgba8(&mut staging);
            let buf: Vec<u32> = staging.chunks_exact(4)
                .map(|p| ((p[0] as u32) << 16) | ((p[1] as u32) << 8) | p[2] as u32).collect();
            std::hint::black_box(buf);
            s_rgb.add(t.elapsed());
        }
        s_dec.add(decode_time);
        std::thread::sleep(Duration::from_millis(33));
    }

    println!("Resolução codificada: {}x{}\n", tw, th);
    for s in [&s_cap, &s_ds, &s_yuv, &s_enc, &s_ser, &s_try, &s_de, &s_dec, &s_rgb] { s.print(); }
    let avg = |v: &Vec<usize>| if v.is_empty() { 0 } else { v.iter().sum::<usize>() / v.len() } as f64 / 1024.0;
    println!("\nKeyframe H.264: média {:.0} KB -> JSON {:.0} KB (x{:.1})", avg(&key_sizes), avg(&json_key), avg(&json_key) / avg(&key_sizes).max(0.001));
    println!("P-frame  H.264: média {:.1} KB -> JSON {:.1} KB", avg(&p_sizes), avg(&json_p));
    println!("Pacotes JSON > 1 MB (limite gossipsub, descartados): {}/{}", too_large, frames);
}
