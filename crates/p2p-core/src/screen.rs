use openh264::encoder::{Encoder, EncoderConfig, FrameRate, IntraFramePeriod, RateControlMode, SpsPpsStrategy, UsageType};
use openh264::formats::{RgbaSliceU8, YUVBuffer};
use openh264::OpenH264API;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use xcap::Monitor;

/// Informações sobre uma tela/monitor disponível para captura
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenInfo {
    pub id: u32,
    pub name: String,
    pub width: u32,
    pub height: u32,
    pub is_primary: bool,
}

/// Tipo de codec de vídeo do pacote
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VideoCodec {
    Jpeg,
    H264,
}

/// Pacote de transmissão de quadro de vídeo P2P (H.264 ou JPEG)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenPacket {
    pub stream_id: String,
    pub sender_pubkey: String,
    pub sender_name: String,
    pub frame_seq: u64,
    pub width: u32,
    pub height: u32,
    pub timestamp_ms: u64,
    pub codec: VideoCodec,
    pub is_keyframe: bool,
    pub video_data: Vec<u8>,
}

impl ScreenPacket {
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Motor de Captura de Tela P2P com suporte a H.264
pub struct ScreenCaptureEngine {
    is_streaming: Arc<AtomicBool>,
}

impl ScreenCaptureEngine {
    pub fn new() -> Self {
        Self {
            is_streaming: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_streaming_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.is_streaming)
    }

    pub fn list_screens() -> Vec<ScreenInfo> {
        match Monitor::all() {
            Ok(monitors) => monitors
                .into_iter()
                .map(|m| ScreenInfo {
                    id: m.id().unwrap_or(0),
                    name: m.name().unwrap_or_else(|_| "Display".to_string()),
                    width: m.width().unwrap_or(1920),
                    height: m.height().unwrap_or(1080),
                    is_primary: m.is_primary().unwrap_or(false),
                })
                .collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Cria um encoder H.264 com configurações otimizadas para Screen Sharing em tempo real:
    /// - Keyframe a cada 30 frames (1 segundo) para que novos espectadores não fiquem em tela preta
    /// - UsageType::ScreenContentRealTime para nitidez máxima de texto e janelas
    /// - RateControlMode::Off com skip_frames(false): garante codificação direta sem pular frames por bitrate
    fn create_h264_encoder(fps: u32) -> Option<Encoder> {
        let api = OpenH264API::from_source();
        let config = EncoderConfig::new()
            .usage_type(UsageType::ScreenContentRealTime)
            .rate_control_mode(RateControlMode::Off)
            .skip_frames(false)
            .max_frame_rate(FrameRate::from_hz(fps as f32))
            .sps_pps_strategy(SpsPpsStrategy::ConstantId)
            .intra_frame_period(IntraFramePeriod::from_num_frames(30));

        Encoder::with_api_config(api, config).ok()
    }

    /// Inicia a captura em tempo real codificando em H.264 a 30 FPS
    pub fn start_capture<F>(
        &self,
        stream_id: String,
        sender_pubkey: String,
        sender_name: String,
        monitor_index: usize,
        target_fps: u32,
        mut on_frame: F,
    ) where
        F: FnMut(ScreenPacket) + Send + 'static,
    {
        self.is_streaming.store(true, Ordering::SeqCst);
        let is_running = Arc::clone(&self.is_streaming);
        let fps = target_fps.clamp(10, 60);
        let frame_interval = Duration::from_millis((1000 / fps) as u64);

        std::thread::spawn(move || {
            let mut frame_seq = 0u64;

            let all_monitors = Monitor::all().unwrap_or_default();
            let selected_monitor = all_monitors.into_iter().nth(monitor_index);

            let mut h264_encoder = Self::create_h264_encoder(fps);
            let mut last_dimensions = (0u32, 0u32);

            while is_running.load(Ordering::Relaxed) {
                let start_time = Instant::now();

                let (width, height, raw_rgba) = if let Some(ref monitor) = selected_monitor {
                    match monitor.capture_image() {
                        Ok(image) => {
                            let w = image.width();
                            let h = image.height();

                            // Ajusta para resolução amigável a H.264 (máx 1280px e dimensões pares)
                            let target_w = if w > 1280 { 1280 } else { w } & !1;
                            let target_h = (((h as f32 * (target_w as f32 / w as f32)) as u32) & !1).max(2);

                            let resized = if target_w != w || target_h != h {
                                image::imageops::resize(
                                    &image,
                                    target_w,
                                    target_h,
                                    image::imageops::FilterType::Nearest,
                                )
                            } else {
                                image
                            };

                            (target_w, target_h, resized.into_raw())
                        }
                        Err(_) => Self::generate_synthetic_rgba(frame_seq),
                    }
                } else {
                    Self::generate_synthetic_rgba(frame_seq)
                };

                // Se a tela mudou de resolução, recria o encoder
                if last_dimensions != (width, height) {
                    h264_encoder = Self::create_h264_encoder(fps);
                    last_dimensions = (width, height);
                }

                // Codifica para H.264
                let (codec, is_keyframe, video_bytes) = if let Some(ref mut enc) = h264_encoder {
                    let rgba_src = RgbaSliceU8::new(&raw_rgba, (width as usize, height as usize));
                    let yuv = YUVBuffer::from_rgb_source(rgba_src);
                    let should_force_key = (frame_seq % 30 == 0) || frame_seq == 0;
                    if should_force_key {
                        enc.force_intra_frame();
                    }
                    match enc.encode(&yuv) {
                        Ok(stream) => {
                            let bytes = stream.to_vec();
                            if bytes.is_empty() {
                                // Se o encoder H.264 gerar 0 bytes (ex: Skip), envia fallback JPEG para garantir fluidez
                                let jpeg = Self::encode_jpeg(&raw_rgba, width, height, 60);
                                (VideoCodec::Jpeg, true, jpeg)
                            } else {
                                (VideoCodec::H264, should_force_key, bytes)
                            }
                        }
                        Err(_) => {
                            let jpeg = Self::encode_jpeg(&raw_rgba, width, height, 50);
                            (VideoCodec::Jpeg, true, jpeg)
                        }
                    }
                } else {
                    let jpeg = Self::encode_jpeg(&raw_rgba, width, height, 50);
                    (VideoCodec::Jpeg, true, jpeg)
                };

                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let packet = ScreenPacket {
                    stream_id: stream_id.clone(),
                    sender_pubkey: sender_pubkey.clone(),
                    sender_name: sender_name.clone(),
                    frame_seq,
                    width,
                    height,
                    timestamp_ms: now_ms,
                    codec,
                    is_keyframe,
                    video_data: video_bytes,
                };

                on_frame(packet);
                frame_seq += 1;

                let elapsed = start_time.elapsed();
                if elapsed < frame_interval {
                    std::thread::sleep(frame_interval - elapsed);
                }
            }
        });
    }

    pub fn stop_capture(&self) {
        self.is_streaming.store(false, Ordering::SeqCst);
    }

    /// Inicia uma transmissão de vídeo sintético animado em H.264
    pub fn start_synthetic_video_stream<F>(
        &self,
        stream_id: String,
        sender_pubkey: String,
        sender_name: String,
        target_fps: u32,
        mut on_frame: F,
    ) where
        F: FnMut(ScreenPacket) + Send + 'static,
    {
        self.is_streaming.store(true, Ordering::SeqCst);
        let is_running = Arc::clone(&self.is_streaming);
        let fps = target_fps.clamp(10, 60);
        let frame_interval = Duration::from_millis((1000 / fps) as u64);

        std::thread::spawn(move || {
            let mut frame_seq = 0u64;
            let (width, height) = (640u32, 360u32);
            let mut h264_encoder = Self::create_h264_encoder(fps);

            while is_running.load(Ordering::Relaxed) {
                let start_time = Instant::now();
                let (_, _, raw_rgba) = Self::generate_synthetic_rgba(frame_seq);

                let (codec, is_keyframe, video_bytes) = if let Some(ref mut enc) = h264_encoder {
                    let rgba_src = RgbaSliceU8::new(&raw_rgba, (width as usize, height as usize));
                    let yuv = YUVBuffer::from_rgb_source(rgba_src);
                    let should_force_key = (frame_seq % 30 == 0) || frame_seq == 0;
                    if should_force_key {
                        enc.force_intra_frame();
                    }
                    match enc.encode(&yuv) {
                        Ok(stream) => {
                            let bytes = stream.to_vec();
                            if bytes.is_empty() {
                                let jpeg = Self::encode_jpeg(&raw_rgba, width, height, 60);
                                (VideoCodec::Jpeg, true, jpeg)
                            } else {
                                (VideoCodec::H264, should_force_key, bytes)
                            }
                        }
                        Err(_) => {
                            let jpeg = Self::encode_jpeg(&raw_rgba, width, height, 50);
                            (VideoCodec::Jpeg, true, jpeg)
                        }
                    }
                } else {
                    let jpeg = Self::encode_jpeg(&raw_rgba, width, height, 50);
                    (VideoCodec::Jpeg, true, jpeg)
                };

                let now_ms = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                let packet = ScreenPacket {
                    stream_id: stream_id.clone(),
                    sender_pubkey: sender_pubkey.clone(),
                    sender_name: sender_name.clone(),
                    frame_seq,
                    width,
                    height,
                    timestamp_ms: now_ms,
                    codec,
                    is_keyframe,
                    video_data: video_bytes,
                };

                on_frame(packet);
                frame_seq += 1;

                let elapsed = start_time.elapsed();
                if elapsed < frame_interval {
                    std::thread::sleep(frame_interval - elapsed);
                }
            }
        });
    }

    fn encode_jpeg(raw_rgba: &[u8], width: u32, height: u32, quality: u8) -> Vec<u8> {
        let mut comp_buf = Vec::with_capacity(32 * 1024);
        let encoder = jpeg_encoder::Encoder::new(&mut comp_buf, quality);
        let _ = encoder.encode(
            raw_rgba,
            width as u16,
            height as u16,
            jpeg_encoder::ColorType::Rgba,
        );
        comp_buf
    }

    fn generate_synthetic_rgba(seq: u64) -> (u32, u32, Vec<u8>) {
        let width = 640u32;
        let height = 360u32;
        let mut pixels = vec![255u8; (width * height * 4) as usize];

        let time_sec = seq as f32 * 0.06;
        let center_x = (width / 2) as f32;
        let center_y = (height / 2) as f32;

        for y in 0..height {
            let dy = y as f32 - center_y;
            for x in 0..width {
                let dx = x as f32 - center_x;
                let dist = (dx * dx + dy * dy).sqrt();

                let ring = ((dist * 0.1 - time_sec * 3.0).sin() * 127.0 + 128.0) as u8;
                let scanline = if y % 4 == 0 { 40 } else { 0 };

                let border = if x < 10 || x > width - 10 || y < 10 || y > height - 10 {
                    200u8
                } else {
                    0u8
                };

                let idx = ((y * width + x) * 4) as usize;

                let r = ((ring as f32 * 0.6 + border as f32) as u8).saturating_sub(scanline);
                let g = (((x as f32 / width as f32) * 50.0 + ring as f32 * 0.2) as u8).saturating_sub(scanline);
                let b = ((220.0 - (dist * 0.4).min(180.0) + border as f32) as u8).saturating_sub(scanline);

                let is_banner_bar = y > height / 2 - 25 && y < height / 2 + 25;
                if is_banner_bar {
                    pixels[idx] = 20;
                    pixels[idx + 1] = 20;
                    pixels[idx + 2] = 40;
                } else {
                    pixels[idx] = r;
                    pixels[idx + 1] = g;
                    pixels[idx + 2] = b;
                }
                pixels[idx + 3] = 255;
            }
        }

        (width, height, pixels)
    }
}
