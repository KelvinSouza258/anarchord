//! Fontes de captura de tela, separadas por plataforma.
//!
//! - Desktop (Windows, Linux, macOS): [`desktop`], via xcap.
//! - Android / iOS: a captura exige APIs do app hospedeiro (MediaProjection / ReplayKit), então o
//!   app entrega os frames pelo [`external::ExternalFrameSender`] e o core cuida do resto do pipeline.
//! - Qualquer plataforma: [`SyntheticSource`] para bots e testes.

use super::encoder::{synthetic_frame, RawFrame};
use super::ScreenInfo;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

pub mod external;

#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
mod desktop;

/// Uma fonte de frames de tela. Roda na thread de captura do pipeline.
pub trait CaptureSource: Send + 'static {
    /// Entrega frames RGBA ao `deliver` até `is_running` virar `false`.
    /// Fontes que geram frames por conta própria devem respeitar `frame_interval`.
    fn run(self: Box<Self>, is_running: &AtomicBool, frame_interval: Duration, deliver: &mut dyn FnMut(RawFrame));
}

/// Monitores disponíveis para captura nesta plataforma
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub fn list_screens() -> Vec<ScreenInfo> {
    desktop::list_screens()
}

/// Fonte de captura do monitor `index`, se a plataforma tiver captura nativa
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub fn monitor_source(index: usize) -> Option<Box<dyn CaptureSource>> {
    desktop::monitor_source(index)
}

/// Sem captura nativa (Android, iOS, etc.): o app hospedeiro usa [`external::external_source`]
#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn list_screens() -> Vec<ScreenInfo> {
    Vec::new()
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
pub fn monitor_source(_index: usize) -> Option<Box<dyn CaptureSource>> {
    None
}

/// Vídeo sintético animado, disponível em todas as plataformas
#[derive(Default)]
pub struct SyntheticSource;

impl CaptureSource for SyntheticSource {
    fn run(self: Box<Self>, is_running: &AtomicBool, frame_interval: Duration, deliver: &mut dyn FnMut(RawFrame)) {
        let mut seq = 0u64;
        while is_running.load(Ordering::Relaxed) {
            let start = Instant::now();
            deliver(synthetic_frame(seq));
            seq += 1;
            if let Some(rest) = frame_interval.checked_sub(start.elapsed()) {
                std::thread::sleep(rest);
            }
        }
    }
}
