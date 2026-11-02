//! Verificação temporária do pipeline real de captura (rodar com --release)
use p2p_core::screen::{max_width_for_quality, ScreenCaptureEngine};
use std::sync::mpsc;
use std::time::{Duration, Instant};

fn main() {
    tracing_subscriber::fmt().with_max_level(tracing::Level::INFO).init();
    let quality: u32 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(720);
    let engine = ScreenCaptureEngine::new();
    let (tx, rx) = mpsc::channel();
    engine.start_capture("screen:teste".into(), "pk".into(), "Teste".into(), 0, 30, max_width_for_quality(quality), move |pkt| {
        let _ = tx.send(pkt);
    });

    let start = Instant::now();
    let (mut n, mut keys, mut bytes) = (0u32, 0u32, 0usize);
    let mut dims = (0, 0);
    while start.elapsed() < Duration::from_secs(5) {
        if let Ok(p) = rx.recv_timeout(Duration::from_millis(100)) {
            n += 1;
            keys += p.is_keyframe as u32;
            bytes += p.video_data.len();
            dims = (p.width, p.height);
        }
    }
    engine.stop_capture();
    println!("{}p -> {}x{} | {} pacotes em 5s ({:.1} FPS) | {} keyframes | média {:.1} KB",
        quality, dims.0, dims.1, n, n as f32 / 5.0, keys, bytes as f32 / n.max(1) as f32 / 1024.0);
}
