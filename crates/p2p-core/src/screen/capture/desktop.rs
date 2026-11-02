//! Captura de tela em desktop (Windows, Linux, macOS) via xcap.

use super::CaptureSource;
use crate::screen::encoder::RawFrame;
use crate::screen::ScreenInfo;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use xcap::Monitor;

pub fn list_screens() -> Vec<ScreenInfo> {
    Monitor::all()
        .map(|monitors| {
            monitors
                .into_iter()
                .map(|m| ScreenInfo {
                    id: m.id().unwrap_or(0),
                    name: m.name().unwrap_or_else(|_| "Display".to_string()),
                    width: m.width().unwrap_or(1920),
                    height: m.height().unwrap_or(1080),
                    is_primary: m.is_primary().unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default()
}

pub fn monitor_source(index: usize) -> Option<Box<dyn CaptureSource>> {
    // Confirma que o monitor existe; o objeto em si é criado na thread de captura
    Monitor::all().ok()?.into_iter().nth(index)?;
    Some(Box::new(MonitorSource { index }))
}

struct MonitorSource {
    index: usize,
}

impl CaptureSource for MonitorSource {
    /// Prefere a sessão contínua do xcap (`video_recorder`: no Windows, Windows Graphics Capture),
    /// que só entrega frames quando a tela muda. Se não estiver disponível, cai para `capture_image`
    /// ritmado pelo FPS, que no Windows recria a sessão a cada frame (~33 ms por captura).
    fn run(self: Box<Self>, is_running: &AtomicBool, frame_interval: Duration, deliver: &mut dyn FnMut(RawFrame)) {
        let Some(monitor) = Monitor::all().ok().and_then(|m| m.into_iter().nth(self.index)) else {
            tracing::warn!("Monitor {} não encontrado", self.index);
            return;
        };

        match monitor.video_recorder() {
            Ok((recorder, frames)) if recorder.start().is_ok() => {
                tracing::info!("Captura contínua de tela iniciada (monitor {})", self.index);
                while is_running.load(Ordering::Relaxed) {
                    let Ok(mut frame) = frames.recv_timeout(Duration::from_millis(100)) else { continue };
                    // Descarta frames acumulados e fica só com o mais recente
                    while let Ok(newer) = frames.try_recv() {
                        frame = newer;
                    }
                    deliver(RawFrame { width: frame.width, height: frame.height, rgba: frame.raw });
                }
                let _ = recorder.stop();
            }
            _ => {
                tracing::warn!("Captura contínua indisponível; usando capture_image a cada frame");
                while is_running.load(Ordering::Relaxed) {
                    let start = Instant::now();
                    match monitor.capture_image() {
                        Ok(image) => {
                            let (width, height) = (image.width(), image.height());
                            deliver(RawFrame { width, height, rgba: image.into_raw() });
                        }
                        Err(e) => tracing::warn!("Erro xcap capture_image: {:?}", e),
                    }
                    if let Some(rest) = frame_interval.checked_sub(start.elapsed()) {
                        std::thread::sleep(rest);
                    }
                }
            }
        }
    }
}
