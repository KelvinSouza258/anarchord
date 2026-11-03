//! Compartilhamento de tela P2P.
//!
//! - [`encoder`]: RGBA -> H.264/JPEG (`ScreenPacket`), igual em todas as plataformas.
//! - [`decoder`]: `ScreenPacket` -> RGBA para quem exibe, igual em todas as plataformas.
//! - [`capture`]: de onde vêm os frames, separado por plataforma (desktop nativo, app hospedeiro, sintético).

pub mod capture;
pub mod decoder;
pub mod encoder;

pub use capture::external::{external_source, ExternalFrameSender, ExternalSource};
pub use capture::{CaptureSource, SyntheticSource};
pub use decoder::{DecodedFrame, KeyframeGate, ScreenDecoder};
pub use encoder::{max_width_for_quality, target_bitrate_bps, FrameEncoder, RawFrame};

use encoder::downscale_rgba;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Informações sobre uma tela/monitor disponível para captura
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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

/// Anúncio leve de uma transmissão, publicado a cada ~2 s no tópico de telas do espaço.
/// Os quadros vão num tópico próprio da stream ([`crate::community::screen_stream_topic`]),
/// assinado só por quem está assistindo.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScreenAnnounce {
    pub stream_id: String,
    pub sender_pubkey: String,
    pub sender_name: String,
    pub width: u32,
    pub height: u32,
}

impl ScreenAnnounce {
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::wire::encode(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::wire::WireError> {
        crate::wire::decode_as(bytes)
    }
}

impl ScreenPacket {
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::wire::encode(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::wire::WireError> {
        crate::wire::decode_as(bytes)
    }
}

/// Identificação de quem transmite, copiada em cada `ScreenPacket`
#[derive(Debug, Clone)]
pub struct StreamIdentity {
    pub stream_id: String,
    pub sender_pubkey: String,
    pub sender_name: String,
}

/// Motor de Captura de Tela P2P com suporte a H.264
pub struct ScreenCaptureEngine {
    /// Flag da sessão de captura atual. Cada start cria uma flag nova, de modo que as threads
    /// de uma sessão anterior (que ficam com a flag antiga) encerram mesmo que um novo start
    /// aconteça logo após o stop, antes de elas perceberem a parada.
    session: Mutex<Arc<AtomicBool>>,
    /// Pedido de keyframe imediato (alguém começou a assistir)
    keyframe_request: Arc<AtomicBool>,
}

impl Default for ScreenCaptureEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScreenCaptureEngine {
    pub fn new() -> Self {
        Self {
            session: Mutex::new(Arc::new(AtomicBool::new(false))),
            keyframe_request: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_streaming(&self) -> bool {
        self.lock_session().load(Ordering::SeqCst)
    }

    /// Encerra a sessão anterior (se houver) e retorna a flag de uma sessão nova, já ativa
    fn begin_session(&self) -> Arc<AtomicBool> {
        let mut session = self.lock_session();
        session.store(false, Ordering::SeqCst);
        *session = Arc::new(AtomicBool::new(true));
        Arc::clone(&session)
    }

    fn lock_session(&self) -> std::sync::MutexGuard<'_, Arc<AtomicBool>> {
        self.session.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Monitores disponíveis nesta plataforma (vazio onde não há captura nativa, ex.: Android/iOS)
    pub fn list_screens() -> Vec<ScreenInfo> {
        capture::list_screens()
    }

    /// Captura o monitor `monitor_index` e transmite em H.264.
    /// max_width: Resolução horizontal máxima (ex: 1920 para 1080p, 1280 para 720p, 960 para 540p, 854 para 480p)
    /// Sem captura nativa ou sem o monitor pedido, transmite vídeo sintético.
    pub fn start_capture<F>(
        &self,
        stream_id: String,
        sender_pubkey: String,
        sender_name: String,
        monitor_index: usize,
        target_fps: u32,
        max_width: u32,
        on_frame: F,
    ) where
        F: FnMut(ScreenPacket) + Send + 'static,
    {
        let source = capture::monitor_source(monitor_index).unwrap_or_else(|| {
            tracing::warn!("Monitor {} indisponível; transmitindo vídeo sintético", monitor_index);
            Box::new(SyntheticSource)
        });
        let identity = StreamIdentity { stream_id, sender_pubkey, sender_name };
        self.start_with_source(source, identity, target_fps, max_width, on_frame);
    }

    /// Inicia uma transmissão de vídeo sintético animado em H.264 (bots e testes)
    pub fn start_synthetic_video_stream<F>(
        &self,
        stream_id: String,
        sender_pubkey: String,
        sender_name: String,
        target_fps: u32,
        on_frame: F,
    ) where
        F: FnMut(ScreenPacket) + Send + 'static,
    {
        let identity = StreamIdentity { stream_id, sender_pubkey, sender_name };
        self.start_with_source(Box::new(SyntheticSource), identity, target_fps, u32::MAX, on_frame);
    }

    /// Pipeline de transmissão a partir de qualquer fonte de frames (ex.: [`external_source`] em mobile).
    ///
    /// Duas threads:
    /// 1. Captura: roda a fonte, reduz a resolução e repassa só o frame mais recente.
    /// 2. Encoder: codifica no máximo `target_fps` frames por segundo. Sem frames novos (tela parada),
    ///    reenvia o último como keyframe a cada segundo, para quem entrar na transmissão conseguir ver.
    pub fn start_with_source<F>(
        &self,
        source: Box<dyn CaptureSource>,
        identity: StreamIdentity,
        target_fps: u32,
        max_width: u32,
        mut on_frame: F,
    ) where
        F: FnMut(ScreenPacket) + Send + 'static,
    {
        let is_running = self.begin_session();
        let is_running_capture = Arc::clone(&is_running);
        let fps = target_fps.clamp(10, 60);
        let frame_interval = Duration::from_millis((1000 / fps) as u64);
        let max_width = if max_width > 0 { max_width } else { 1280 };

        // Capacidade 1 + try_send: o encoder sempre pega o frame mais recente, sem fila acumulando atraso
        let (tx_raw, rx_raw) = std::sync::mpsc::sync_channel::<RawFrame>(1);
        let keyframe_request = Arc::clone(&self.keyframe_request);

        std::thread::spawn(move || {
            source.run(&is_running_capture, frame_interval, &mut |frame| {
                let frame = downscale_rgba(frame.rgba, frame.width, frame.height, max_width);
                let _ = tx_raw.try_send(frame);
            });
        });

        std::thread::spawn(move || {
            let mut encoder = FrameEncoder::new(fps);
            let keyframe_request = Arc::clone(&keyframe_request);
            let mut last_frame: Option<RawFrame> = None;

            while is_running.load(Ordering::Relaxed) {
                let start_time = Instant::now();
                if keyframe_request.swap(false, Ordering::SeqCst) {
                    encoder.request_keyframe();
                }

                let frame = match rx_raw.recv_timeout(frame_interval) {
                    Ok(f) => f,
                    // Tela parada: reenvia o último frame só quando um keyframe periódico é devido
                    Err(_) => match last_frame.take() {
                        Some(f) if encoder.keyframe_due() => f,
                        other => {
                            last_frame = other;
                            continue;
                        }
                    },
                };

                let packet = encoder.encode(&frame, &identity.stream_id, &identity.sender_pubkey, &identity.sender_name);
                if packet.frame_seq % 30 == 0 {
                    tracing::info!(
                        "⏱️ [ENCODER] Frame #{}: {} ms, {:.1} KB",
                        packet.frame_seq,
                        start_time.elapsed().as_millis(),
                        packet.video_data.len() as f32 / 1024.0
                    );
                }
                on_frame(packet);
                last_frame = Some(frame);

                if let Some(rest) = frame_interval.checked_sub(start_time.elapsed()) {
                    std::thread::sleep(rest);
                }
            }
        });
    }

    /// Faz o próximo quadro da transmissão sair como keyframe, para quem acabou de começar a
    /// assistir não esperar o keyframe periódico
    pub fn request_keyframe(&self) {
        self.keyframe_request.store(true, Ordering::SeqCst);
    }

    pub fn stop_capture(&self) {
        self.lock_session().store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity() -> StreamIdentity {
        StreamIdentity { stream_id: "s".into(), sender_pubkey: "pk".into(), sender_name: "Alice".into() }
    }

    #[test]
    fn test_restart_does_not_revive_previous_session() {
        let engine = ScreenCaptureEngine::new();
        assert!(!engine.is_streaming());

        let old_session = engine.begin_session();
        engine.stop_capture();
        let new_session = engine.begin_session();

        // As threads da sessão antiga continuam vendo a parada mesmo após o novo start
        assert!(!old_session.load(Ordering::SeqCst));
        assert!(new_session.load(Ordering::SeqCst));
        assert!(engine.is_streaming());

        engine.stop_capture();
        assert!(!new_session.load(Ordering::SeqCst));
        assert!(!engine.is_streaming());
    }

    #[test]
    fn test_synthetic_stream_delivers_decodable_frames() {
        let engine = ScreenCaptureEngine::new();
        let (tx, rx) = std::sync::mpsc::channel();
        engine.start_synthetic_video_stream("s".into(), "pk".into(), "Alice".into(), 30, move |p| {
            let _ = tx.send(p);
        });
        let packets: Vec<ScreenPacket> = (0..5).filter_map(|_| rx.recv_timeout(Duration::from_secs(5)).ok()).collect();
        engine.stop_capture();

        assert_eq!(packets.len(), 5);
        assert!(packets[0].is_keyframe);
        let mut decoder = ScreenDecoder::new();
        for p in &packets {
            let frame = decoder.decode(p.codec, &p.video_data).expect("todos os quadros deveriam decodificar");
            assert_eq!((frame.width, frame.height), (640, 360));
        }
    }

    /// Caminho usado por Android/iOS: o app hospedeiro entrega frames e o core transmite
    #[test]
    fn test_external_source_frames_are_downscaled_and_streamed() {
        let engine = ScreenCaptureEngine::new();
        let (source, sender) = external_source();
        let (tx, rx) = std::sync::mpsc::channel();
        engine.start_with_source(Box::new(source), identity(), 30, 640, move |p| {
            let _ = tx.send(p);
        });

        let big = encoder::synthetic_frame(0);
        let upscaled: Vec<u8> = (0..720).flat_map(|y| (0..1280).flat_map(move |x| {
            let i = ((y / 2) * 640 + x / 2) * 4;
            [i, i + 1, i + 2, i + 3]
        })).map(|i| big.rgba[i]).collect();
        let mut packet = None;
        for _ in 0..50 {
            sender.push(1280, 720, upscaled.clone());
            if let Ok(p) = rx.recv_timeout(Duration::from_millis(100)) {
                packet = Some(p);
                break;
            }
        }
        engine.stop_capture();

        let packet = packet.expect("o pipeline deveria transmitir o frame externo");
        assert_eq!((packet.width, packet.height), (640, 360), "frame deveria ser reduzido para max_width");
        assert!(packet.is_keyframe);
    }
}
