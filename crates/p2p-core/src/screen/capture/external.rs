//! Fonte de frames entregues de fora do core: o app hospedeiro captura a tela com as APIs da
//! plataforma (ex.: MediaProjection no Android, ReplayKit no iOS) e repassa os frames RGBA aqui.

use super::CaptureSource;
use crate::screen::encoder::RawFrame;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::time::Duration;

/// Lado do core: consumido pelo pipeline de captura
pub struct ExternalSource {
    rx: Receiver<RawFrame>,
}

/// Lado do app hospedeiro: entrega os frames capturados
#[derive(Clone)]
pub struct ExternalFrameSender {
    tx: SyncSender<RawFrame>,
}

/// Cria o par (fonte para o pipeline, remetente para o app hospedeiro)
pub fn external_source() -> (ExternalSource, ExternalFrameSender) {
    let (tx, rx) = sync_channel(2);
    (ExternalSource { rx }, ExternalFrameSender { tx })
}

impl ExternalFrameSender {
    /// Entrega um frame RGBA (4 bytes por pixel, sem padding). Se o pipeline estiver ocupado
    /// o frame é descartado; retorna `false` quando descartado ou quando a transmissão acabou.
    pub fn push(&self, width: u32, height: u32, rgba: Vec<u8>) -> bool {
        if rgba.len() != (width as usize) * (height as usize) * 4 {
            return false;
        }
        match self.tx.try_send(RawFrame { width, height, rgba }) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }
}

impl CaptureSource for ExternalSource {
    fn run(self: Box<Self>, is_running: &AtomicBool, _frame_interval: Duration, deliver: &mut dyn FnMut(RawFrame)) {
        while is_running.load(Ordering::Relaxed) {
            match self.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(frame) => deliver(frame),
                Err(RecvTimeoutError::Timeout) => continue,
                Err(RecvTimeoutError::Disconnected) => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rejects_frame_with_wrong_size() {
        let (_source, sender) = external_source();
        assert!(!sender.push(4, 4, vec![0; 10]));
        assert!(sender.push(4, 4, vec![0; 4 * 4 * 4]));
    }
}
