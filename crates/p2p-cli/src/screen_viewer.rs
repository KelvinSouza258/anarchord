use minifb::{Key, Window, WindowOptions};
use p2p_core::screen::{DecodedFrame, ScreenDecoder, VideoCodec};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Exibidor gráfico de tela em janela nativa ultraleve via minifb com métricas de telemetria em tempo real.
/// A decodificação fica no core (`ScreenDecoder`); aqui só há a janela e a conversão para o formato do minifb.
pub struct ScreenViewer;

impl ScreenViewer {
    /// Abre uma janela nativa independente e renderiza os quadros H.264 (ou JPEG) recebidos em tempo real.
    /// Exibe no título da janela: FPS real, bitrate em tempo real (KB/s), total recebido e resolução atual.
    pub fn spawn_window(
        title: String,
        mut initial_width: usize,
        mut initial_height: usize,
        rx_video_frames: Arc<Mutex<Receiver<(VideoCodec, Vec<u8>)>>>,
        is_active: Arc<AtomicBool>,
    ) {
        std::thread::spawn(move || {
            if initial_width == 0 {
                initial_width = 1280;
            }
            if initial_height == 0 {
                initial_height = 720;
            }

            let mut window = match Window::new(
                &format!("📺 Anarchord Screen [{}] - Conectando...", title),
                initial_width,
                initial_height,
                WindowOptions {
                    resize: true,
                    scale: minifb::Scale::X1,
                    ..WindowOptions::default()
                },
            ) {
                Ok(w) => w,
                Err(e) => {
                    tracing::error!("Erro ao abrir janela de vídeo: {:?}", e);
                    is_active.store(false, Ordering::SeqCst);
                    return;
                }
            };

            window.set_target_fps(60);

            let mut current_buffer: Vec<u32> = vec![0; initial_width * initial_height];
            let mut curr_w = initial_width;
            let mut curr_h = initial_height;
            let mut decoder = ScreenDecoder::new();

            // Variáveis de telemetria (FPS e velocidade de rede)
            let mut last_metrics_update = Instant::now();
            let mut frames_this_second = 0u32;
            let mut bytes_this_second = 0usize;
            let mut total_bytes_received = 0u64;
            let mut current_codec_name = "H.264";

            while window.is_open() && !window.is_key_down(Key::Escape) && is_active.load(Ordering::Relaxed) {
                let mut incoming_packets = Vec::new();
                if let Ok(rx) = rx_video_frames.lock() {
                    while let Ok(pkt) = rx.try_recv() {
                        incoming_packets.push(pkt);
                    }
                }

                let mut had_new_frame = false;

                for (codec, data) in incoming_packets {
                    bytes_this_second += data.len();
                    total_bytes_received += data.len() as u64;
                    current_codec_name = match codec {
                        VideoCodec::H264 => "H.264",
                        VideoCodec::Jpeg => "JPEG",
                    };

                    if let Some(frame) = decoder.decode(codec, &data) {
                        Self::copy_to_window_buffer(frame, &mut current_buffer, &mut curr_w, &mut curr_h);
                        frames_this_second += 1;
                        had_new_frame = true;
                    }
                }

                // Atualiza a barra de título com estatísticas a cada 500ms
                if last_metrics_update.elapsed() >= Duration::from_millis(500) {
                    let elapsed_sec = last_metrics_update.elapsed().as_secs_f32();
                    let current_fps = (frames_this_second as f32 / elapsed_sec).round() as u32;
                    let current_kbps = (bytes_this_second as f32 / 1024.0) / elapsed_sec;
                    let total_mb = (total_bytes_received as f64) / (1024.0 * 1024.0);

                    window.set_title(&format!(
                        "📺 [{}] {} | {}x{} | {} FPS | {:.1} KB/s ({:.2} MB) | ESC para fechar",
                        current_codec_name, title, curr_w, curr_h, current_fps, current_kbps, total_mb
                    ));

                    frames_this_second = 0;
                    bytes_this_second = 0;
                    last_metrics_update = Instant::now();
                }

                if had_new_frame {
                    if window.update_with_buffer(&current_buffer, curr_w, curr_h).is_err() {
                        break;
                    }
                } else {
                    window.update();
                    std::thread::sleep(Duration::from_millis(2));
                }
            }

            is_active.store(false, Ordering::SeqCst);
        });
    }

    /// Converte RGBA para o formato 0RGB (u32) que o minifb exibe
    fn copy_to_window_buffer(frame: &DecodedFrame, buffer: &mut Vec<u32>, curr_w: &mut usize, curr_h: &mut usize) {
        if frame.width != *curr_w || frame.height != *curr_h {
            *curr_w = frame.width;
            *curr_h = frame.height;
        }
        buffer.resize(frame.width * frame.height, 0);
        for (dst, px) in buffer.iter_mut().zip(frame.rgba.chunks_exact(4)) {
            *dst = (px[0] as u32) << 16 | (px[1] as u32) << 8 | px[2] as u32;
        }
    }
}
