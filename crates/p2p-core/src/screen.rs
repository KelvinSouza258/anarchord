use openh264::encoder::Encoder;
use openh264::formats::{RgbaSliceU8, YUVBuffer};
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
    /// Fallback JPEG legado (quadro completo independente)
    Jpeg,
    /// H.264 / AVC de alta performance com compressão inter-frames
    H264,
}

/// Pacote de transmissão de quadro de vídeo P2P (H.264 ou JPEG)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenPacket {
    /// Identificador do fluxo (ex: "screen:<pubkey_curta>")
    pub stream_id: String,
    /// Chave pública do apresentador
    pub sender_pubkey: String,
    /// Apelido do apresentador
    pub sender_name: String,
    /// Número sequencial do quadro
    pub frame_seq: u64,
    /// Largura do quadro transmitido
    pub width: u32,
    /// Altura do quadro transmitido
    pub height: u32,
    /// Timestamp Unix em milissegundos
    pub timestamp_ms: u64,
    /// Codec de vídeo utilizado neste pacote
    pub codec: VideoCodec,
    /// Indica se o quadro é um Keyframe / I-Frame (imagem completa sem depender do anterior)
    pub is_keyframe: bool,
    /// Dados binários codificados do vídeo (NAL units H.264 ou bytes JPEG)
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

    /// Retorna handle atômico para verificar ou alternar status de transmissão
    pub fn is_streaming_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.is_streaming)
    }

    /// Lista os monitores físicos detectados pelo sistema operacional
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

    /// Inicia a captura em tempo real codificando em H.264 a 30 FPS com baixíssimo uso de banda
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

            // Busca os monitores disponíveis
            let all_monitors = Monitor::all().unwrap_or_default();
            let selected_monitor = all_monitors.into_iter().nth(monitor_index);

            let mut h264_encoder: Option<Encoder> = None;

            while is_running.load(Ordering::Relaxed) {
                let start_time = Instant::now();

                let (width, height, raw_rgba) = if let Some(ref monitor) = selected_monitor {
                    match monitor.capture_image() {
                        Ok(image) => {
                            let w = image.width();
                            let h = image.height();

                            // Ajusta para resolução amigável a H.264 (downscale 720p se > 1280, e dimensões pares)
                            let target_w = if w > 1280 { 1280 } else { w } & !1;
                            let target_h = (((h as f32 * (target_w as f32 / w as f32)) as u32) & !1).max(2);

                            let resized = if target_w != w || target_h != h {
                                image::imageops::resize(
                                    &image,
                                    target_w,
                                    target_h,
                                    image::imageops::FilterType::Triangle,
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

                // Inicializa o encoder H.264
                if h264_encoder.is_none() {
                    h264_encoder = Encoder::new().ok();
                }

                // Codifica o frame RGBA para H.264 (com fallback para JPEG se o encoder falhar)
                let (codec, is_keyframe, video_bytes) = if let Some(ref mut enc) = h264_encoder {
                    let rgba_src = RgbaSliceU8::new(&raw_rgba, (width as usize, height as usize));
                    let yuv = YUVBuffer::from_rgb_source(rgba_src);
                    match enc.encode(&yuv) {
                        Ok(stream) => {
                            let bytes = stream.to_vec();
                            let is_key = (frame_seq % 60 == 0) || frame_seq == 0;
                            (VideoCodec::H264, is_key, bytes)
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

    /// Para a captura ativa
    pub fn stop_capture(&self) {
        self.is_streaming.store(false, Ordering::SeqCst);
    }

    /// Inicia uma transmissão de vídeo sintético animado em H.264 (para bots/servidores headless)
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
            let mut h264_encoder = Encoder::new().ok();

            while is_running.load(Ordering::Relaxed) {
                let start_time = Instant::now();
                let (_, _, raw_rgba) = Self::generate_synthetic_rgba(frame_seq);

                let (codec, is_keyframe, video_bytes) = if let Some(ref mut enc) = h264_encoder {
                    let rgba_src = RgbaSliceU8::new(&raw_rgba, (width as usize, height as usize));
                    let yuv = YUVBuffer::from_rgb_source(rgba_src);
                    match enc.encode(&yuv) {
                        Ok(stream) => {
                            let bytes = stream.to_vec();
                            let is_key = (frame_seq % 60 == 0) || frame_seq == 0;
                            (VideoCodec::H264, is_key, bytes)
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

    /// Codifica buffer RGBA em JPEG (usado como fallback)
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

    /// Gera quadro sintético dinâmico RGBA de alta fidelidade estilo Anarchord TV
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

                // Padrão de anéis concêntricos pulsantes (Efeito Radar / Cyber Neon)
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
