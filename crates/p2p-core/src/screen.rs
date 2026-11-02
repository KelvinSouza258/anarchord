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

/// Pacote de transmissão de quadro de vídeo P2P compactado em JPEG
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
    /// Dados binários do quadro compactado em JPEG
    pub jpeg_data: Vec<u8>,
}

impl ScreenPacket {
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Motor de Captura de Tela P2P
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

    /// Inicia a captura em thread dedicada com taxa de quadros e qualidade controladas
    /// - `monitor_index`: Índice do monitor selecionado (0 para primário padrão)
    /// - `target_fps`: Taxa alvo de quadros (ex: 15 a 20 FPS para streaming P2P fluido e leve)
    /// - `jpeg_quality`: Qualidade de compressão (1 a 100, padrão recomendado 60-70)
    pub fn start_capture<F>(
        &self,
        stream_id: String,
        sender_pubkey: String,
        sender_name: String,
        monitor_index: usize,
        target_fps: u32,
        jpeg_quality: u8,
        mut on_frame: F,
    ) where
        F: FnMut(ScreenPacket) + Send + 'static,
    {
        self.is_streaming.store(true, Ordering::SeqCst);
        let is_running = Arc::clone(&self.is_streaming);
        let frame_interval = Duration::from_millis((1000 / target_fps.max(1)) as u64);

        std::thread::spawn(move || {
            let mut frame_seq = 0u64;

            // Busca os monitores disponíveis
            let all_monitors = Monitor::all().unwrap_or_default();
            let selected_monitor = all_monitors.into_iter().nth(monitor_index);

            while is_running.load(Ordering::Relaxed) {
                let start_time = Instant::now();

                // Captura a tela física ou gera padrão de teste caso esteja em VPS headless
                let (width, height, jpeg_bytes) = if let Some(ref monitor) = selected_monitor {
                    match monitor.capture_image() {
                        Ok(image) => {
                            let w = image.width();
                            let h = image.height();

                            // Downscale proporcional se resolução for 2K/4K para economizar banda
                            let target_w = if w > 1280 { 1280 } else { w };
                            let target_h = (h as f32 * (target_w as f32 / w as f32)) as u32;

                            let resized = if target_w != w {
                                image::imageops::resize(
                                    &image,
                                    target_w,
                                    target_h,
                                    image::imageops::FilterType::Triangle,
                                )
                            } else {
                                image
                            };

                            let mut comp_buf = Vec::with_capacity(32 * 1024);
                            let encoder = jpeg_encoder::Encoder::new(&mut comp_buf, jpeg_quality);
                            let encode_res = encoder.encode(
                                resized.as_raw(),
                                target_w as u16,
                                target_h as u16,
                                jpeg_encoder::ColorType::Rgba,
                            );

                            if encode_res.is_ok() {
                                (target_w, target_h, comp_buf)
                            } else {
                                Self::generate_synthetic_frame(frame_seq, jpeg_quality)
                            }
                        }
                        Err(_) => Self::generate_synthetic_frame(frame_seq, jpeg_quality),
                    }
                } else {
                    Self::generate_synthetic_frame(frame_seq, jpeg_quality)
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
                    jpeg_data: jpeg_bytes,
                };

                on_frame(packet);
                frame_seq += 1;

                // Controle preciso de cadência de FPS
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

    /// Gera quadro sintético para ambientes headless (ex: Linux VPS / Docker) sem tela física
    fn generate_synthetic_frame(seq: u64, quality: u8) -> (u32, u32, Vec<u8>) {
        let width = 640u32;
        let height = 360u32;
        let mut pixels = vec![0u8; (width * height * 3) as usize];

        // Animação de barras de cor e grid de teste
        let offset = ((seq * 5) % 255) as u8;
        for y in 0..height {
            for x in 0..width {
                let idx = ((y * width + x) * 3) as usize;
                pixels[idx] = ((x * 255 / width) as u8).wrapping_add(offset);
                pixels[idx + 1] = ((y * 255 / height) as u8).wrapping_sub(offset);
                pixels[idx + 2] = 160;
            }
        }

        let mut comp_buf = Vec::new();
        let encoder = jpeg_encoder::Encoder::new(&mut comp_buf, quality);
        let _ = encoder.encode(
            &pixels,
            width as u16,
            height as u16,
            jpeg_encoder::ColorType::Rgb,
        );

        (width, height, comp_buf)
    }
}
