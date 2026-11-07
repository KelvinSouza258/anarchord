//! Codificação de frames de tela (H.264 com fallback JPEG). Independente de plataforma.

use super::{ScreenPacket, VideoCodec};
use openh264::encoder::{
    BitRate, Complexity, Encoder, EncoderConfig, FrameRate, FrameType, IntraFramePeriod, RateControlMode, SpsPpsStrategy,
    UsageType,
};
use openh264::formats::{RgbaSliceU8, YUVBuffer};
use openh264::OpenH264API;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Frame RGBA cru (sem padding entre linhas)
pub struct RawFrame {
    pub width: u32,
    pub height: u32,
    pub rgba: Vec<u8>,
}

/// Converte a qualidade pedida pelo usuário (ex.: 720 de "720p") na largura máxima de captura.
/// Valores fora da tabela são tratados como largura direta.
pub fn max_width_for_quality(quality: u32) -> u32 {
    match quality {
        1080 => 1920,
        720 => 1280,
        540 => 960,
        480 => 854,
        360 => 640,
        other => other,
    }
}

/// Bitrate alvo do H.264: ~0,1 bit por pixel por frame, entre 1 e 8 Mbps
/// (≈2,8 Mbps em 720p30 e ≈6,2 Mbps em 1080p30)
pub fn target_bitrate_bps(width: u32, height: u32, fps: u32) -> u32 {
    let bps = width as u64 * height as u64 * fps as u64 / 10;
    bps.clamp(1_000_000, 8_000_000) as u32
}

/// Reduz a resolução (vizinho mais próximo) para no máximo `max_width`, mantendo a proporção.
/// Largura e altura saem pares, como o H.264 (YUV 4:2:0) exige.
pub fn downscale_rgba(raw: Vec<u8>, w: u32, h: u32, max_width: u32) -> RawFrame {
    let tw = (w.min(max_width) & !1).max(2);
    let th = (((h as f32 * (tw as f32 / w as f32)) as u32) & !1).max(2);
    if tw == w && th == h {
        return RawFrame { width: w, height: h, rgba: raw };
    }
    let (tw_us, th_us, w_us, h_us) = (tw as usize, th as usize, w as usize, h as usize);
    let mut out = vec![0u8; tw_us * th_us * 4];
    for y in 0..th_us {
        let src_row = (y * h_us / th_us) * w_us * 4;
        let dst_row = y * tw_us * 4;
        for x in 0..tw_us {
            let src = src_row + (x * w_us / tw_us) * 4;
            let dst = dst_row + x * 4;
            out[dst..dst + 4].copy_from_slice(&raw[src..src + 4]);
        }
    }
    RawFrame { width: tw, height: th, rgba: out }
}

/// Tela sintética animada (640x360), usada por bots/testes e quando não há monitor disponível
pub fn synthetic_frame(seq: u64) -> RawFrame {
    let width = 640u32;
    let height = 360u32;
    let mut pixels = vec![255u8; (width * height * 4) as usize];
    let shift = ((seq * 8) % (width as u64)) as usize;

    // Fundo com gradiente suave e barra animada deslizante
    for y in 0..height as usize {
        let row_offset = y * (width as usize) * 4;
        let y_color = (y * 255 / (height as usize)) as u8;
        for x in 0..width as usize {
            let idx = row_offset + x * 4;
            if (x + shift) % 80 < 12 {
                pixels[idx..idx + 3].copy_from_slice(&[40, 220, 120]);
            } else {
                pixels[idx] = (x * 255 / (width as usize)) as u8;
                pixels[idx + 1] = y_color;
                pixels[idx + 2] = 180;
            }
            pixels[idx + 3] = 255;
        }
    }
    RawFrame { width, height, rgba: pixels }
}

fn encode_jpeg(raw_rgba: &[u8], width: u32, height: u32, quality: u8) -> Vec<u8> {
    let mut comp_buf = Vec::with_capacity(32 * 1024);
    let encoder = jpeg_encoder::Encoder::new(&mut comp_buf, quality);
    let _ = encoder.encode(raw_rgba, width as u16, height as u16, jpeg_encoder::ColorType::Rgba);
    comp_buf
}

fn encoder_threads() -> u16 {
    std::thread::available_parallelism().map_or(1, |n| n.get().min(4) as u16)
}

/// Codificador de frames de tela: H.264 com fallback para JPEG, keyframe periódico por tempo
pub struct FrameEncoder {
    fps: u32,
    h264: Option<Encoder>,
    dimensions: (u32, u32),
    frame_seq: u64,
    last_keyframe: Option<Instant>,
}

impl FrameEncoder {
    /// Intervalo máximo entre keyframes: quem entra na transmissão espera no máximo isso para ver a tela
    const KEYFRAME_INTERVAL: Duration = Duration::from_secs(1);

    pub fn new(fps: u32) -> Self {
        Self { fps, h264: None, dimensions: (0, 0), frame_seq: 0, last_keyframe: None }
    }

    /// Cria o encoder H.264 para tempo real, priorizando velocidade:
    /// - UsageType::CameraVideoRealTime: ~2,5x mais rápido que ScreenContentRealTime (medido no encoder_profile)
    /// - Complexity::Low e controle de taxa por bitrate proporcional à resolução
    /// - Até 4 threads internas: em conteúdo de muito movimento reduz o encode em ~1/3
    /// - Keyframes são forçados por tempo em `encode`, não por contagem de frames
    fn create_h264(width: u32, height: u32, fps: u32) -> Option<Encoder> {
        let config = EncoderConfig::new()
            .usage_type(UsageType::CameraVideoRealTime)
            .complexity(Complexity::Low)
            .rate_control_mode(RateControlMode::Bitrate)
            .bitrate(BitRate::from_bps(target_bitrate_bps(width, height, fps)))
            .skip_frames(true)
            .debug(false)
            .max_frame_rate(FrameRate::from_hz(fps as f32))
            .sps_pps_strategy(SpsPpsStrategy::ConstantId)
            .intra_frame_period(IntraFramePeriod::auto())
            .num_threads(encoder_threads());
        Encoder::with_api_config(OpenH264API::from_source(), config).ok()
    }

    /// Indica se já passou o intervalo do keyframe periódico (ou se nenhum foi enviado ainda)
    /// O próximo frame sai como keyframe (ex.: alguém acabou de começar a assistir)
    pub fn request_keyframe(&mut self) {
        self.last_keyframe = None;
    }

    pub fn keyframe_due(&self) -> bool {
        self.last_keyframe.map_or(true, |t| t.elapsed() >= Self::KEYFRAME_INTERVAL)
    }

    pub fn encode(&mut self, frame: &RawFrame, stream_id: &str, sender_pubkey: &str, sender_name: &str) -> ScreenPacket {
        let (width, height) = (frame.width, frame.height);
        if self.dimensions != (width, height) {
            self.h264 = Self::create_h264(width, height, self.fps);
            self.dimensions = (width, height);
            self.last_keyframe = None;
        }

        let force_key = self.keyframe_due();
        let h264_result = self.h264.as_mut().and_then(|enc| {
            // Conversão RGBA -> YUV com o caminho rápido (AVX2 quando disponível)
            let yuv = YUVBuffer::from_rgba8_source(RgbaSliceU8::new(&frame.rgba, (width as usize, height as usize)));
            if force_key {
                enc.force_intra_frame();
            }
            let stream = enc.encode(&yuv).ok()?;
            let is_key = matches!(stream.frame_type(), FrameType::IDR | FrameType::I);
            let bytes = stream.to_vec();
            (!bytes.is_empty()).then_some((bytes, is_key))
        });

        let (codec, is_keyframe, video_data) = match h264_result {
            Some((bytes, is_key)) => (VideoCodec::H264, is_key, bytes),
            None => (VideoCodec::Jpeg, true, encode_jpeg(&frame.rgba, width, height, 60)),
        };
        if is_keyframe {
            self.last_keyframe = Some(Instant::now());
        }

        let packet = ScreenPacket {
            stream_id: stream_id.to_string(),
            sender_pubkey: sender_pubkey.to_string(),
            sender_name: sender_name.to_string(),
            frame_seq: self.frame_seq,
            width,
            height,
            timestamp_ms: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64,
            codec,
            is_keyframe,
            video_data,
        };
        self.frame_seq += 1;
        packet
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_downscale_keeps_aspect_and_even_dimensions() {
        let raw = vec![7u8; 1921 * 1081 * 4];
        let f = downscale_rgba(raw, 1921, 1081, 1280);
        assert_eq!((f.width % 2, f.height % 2), (0, 0));
        assert_eq!(f.width, 1280);
        assert!((f.height as i32 - 720).abs() <= 2, "altura {} deveria manter ~16:9", f.height);
        assert_eq!(f.rgba.len(), (f.width * f.height * 4) as usize);

        let small = downscale_rgba(vec![1u8; 640 * 360 * 4], 640, 360, 1280);
        assert_eq!((small.width, small.height, small.rgba.len()), (640, 360, 640 * 360 * 4), "não amplia telas menores");
    }

    #[test]
    fn test_quality_and_bitrate_mapping() {
        assert_eq!(max_width_for_quality(720), 1280);
        assert_eq!(max_width_for_quality(1080), 1920);
        assert_eq!(max_width_for_quality(1000), 1000);
        assert_eq!(target_bitrate_bps(1280, 720, 30), 2_764_800);
        assert_eq!(target_bitrate_bps(320, 180, 10), 1_000_000);
        assert_eq!(target_bitrate_bps(3840, 2160, 60), 8_000_000);
    }

    #[test]
    fn test_encoder_keyframe_then_smaller_p_frames() {
        let mut enc = FrameEncoder::new(30);
        let first = enc.encode(&synthetic_frame(0), "s", "pk", "Alice");
        assert_eq!(first.codec, VideoCodec::H264);
        assert!(first.is_keyframe, "primeiro frame precisa ser keyframe");
        assert!(!enc.keyframe_due());

        let second = enc.encode(&synthetic_frame(1), "s", "pk", "Alice");
        assert_eq!(second.codec, VideoCodec::H264);
        assert!(!second.is_keyframe);
        assert!(second.video_data.len() < first.video_data.len());
        assert_eq!((first.frame_seq, second.frame_seq), (0, 1));
    }

    #[test]
    fn test_encoder_forces_keyframe_on_resolution_change() {
        let mut enc = FrameEncoder::new(30);
        enc.encode(&synthetic_frame(0), "s", "pk", "Alice");
        let resized = downscale_rgba(synthetic_frame(1).rgba, 640, 360, 320);
        let packet = enc.encode(&resized, "s", "pk", "Alice");
        assert_eq!((packet.width, packet.height), (320, 180));
        assert!(packet.is_keyframe);
    }
}
