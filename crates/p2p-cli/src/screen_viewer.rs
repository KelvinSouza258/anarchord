use minifb::{Key, ScaleMode, Window, WindowOptions};
use p2p_core::screen::{DecodedFrame, ScreenDecoder, VideoCodec};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Exibidor gráfico de tela em janela nativa ultraleve via minifb com métricas de telemetria em tempo real.
/// A decodificação fica no core (`ScreenDecoder`); aqui só há a janela e a conversão para o formato do minifb.
pub struct ScreenViewer;

impl ScreenViewer {
    /// Calcula a largura e altura inicial da janela respeitando a proporção (aspect ratio) do quadro de vídeo,
    /// limitando a dimensões máximas confortáveis (por padrão 1280x720 quando max_w/max_h forem 0).
    pub fn calculate_initial_window_size(
        frame_w: usize,
        frame_h: usize,
        max_w: usize,
        max_h: usize,
    ) -> (usize, usize) {
        if frame_w == 0 || frame_h == 0 {
            return (1280, 720);
        }

        let max_w = if max_w == 0 { 1280 } else { max_w };
        let max_h = if max_h == 0 { 720 } else { max_h };

        // Se o quadro já cabe dentro dos limites máximos e não é minúsculo (>= 640x360),
        // preserva o tamanho original 1:1.
        if frame_w <= max_w && frame_h <= max_h && frame_w >= 640 && frame_h >= 360 {
            return (frame_w, frame_h);
        }

        let scale = (max_w as f32 / frame_w as f32).min(max_h as f32 / frame_h as f32);
        let win_w = ((frame_w as f32 * scale).round() as usize).max(320);
        let win_h = ((frame_h as f32 * scale).round() as usize).max(180);
        (win_w, win_h)
    }

    /// Abre uma janela nativa independente e renderiza os quadros H.264 (ou JPEG) recebidos em tempo real.
    /// Exibe no título da janela: FPS real, bitrate em tempo real (KB/s), total recebido e resolução atual.
    /// Preserva rigorosamente o aspect ratio do vídeo usando `ScaleMode::AspectRatioStretch`.
    pub fn spawn_window(
        title: String,
        initial_width: usize,
        initial_height: usize,
        rx_video_frames: Arc<Mutex<Receiver<(VideoCodec, Vec<u8>)>>>,
        is_active: Arc<AtomicBool>,
    ) {
        std::thread::spawn(move || {
            let mut decoder = ScreenDecoder::new();
            let mut current_buffer: Vec<u32> = Vec::new();
            let mut curr_w = 0;
            let mut curr_h = 0;

            // Variáveis de telemetria (FPS e velocidade de rede)
            let mut last_metrics_update = Instant::now();
            let mut frames_this_second = 0u32;
            let mut bytes_this_second = 0usize;
            let mut total_bytes_received = 0u64;
            let mut current_codec_name = "H.264";

            let mut window_opt: Option<Window> = None;

            while is_active.load(Ordering::Relaxed) {
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
                        if window_opt.is_none() {
                            let (win_w, win_h) = Self::calculate_initial_window_size(
                                frame.width,
                                frame.height,
                                initial_width,
                                initial_height,
                            );

                            let mut w = match Window::new(
                                &format!("📺 Anarchord Screen [{}]", title),
                                win_w,
                                win_h,
                                WindowOptions {
                                    resize: true,
                                    scale: minifb::Scale::X1,
                                    scale_mode: ScaleMode::AspectRatioStretch,
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
                            w.set_target_fps(60);
                            let _ = w.set_background_color(0, 0, 0);
                            window_opt = Some(w);
                        }

                        Self::copy_to_window_buffer(frame, &mut current_buffer, &mut curr_w, &mut curr_h);
                        frames_this_second += 1;
                        had_new_frame = true;
                    }
                }

                if let Some(ref mut window) = window_opt {
                    if !window.is_open() || window.is_key_down(Key::Escape) {
                        break;
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
                } else {
                    std::thread::sleep(Duration::from_millis(5));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_initial_window_size_16_9() {
        // Full HD 16:9 ajustado para max 1280x720
        let (w, h) = ScreenViewer::calculate_initial_window_size(1920, 1080, 1280, 720);
        assert_eq!((w, h), (1280, 720));
        assert_eq!(w * 9, h * 16);
    }

    #[test]
    fn test_calculate_initial_window_size_4_3() {
        // Resolução 4:3 (1024x768) ajustada para caber em 1280x720 sem distorção
        let (w, h) = ScreenViewer::calculate_initial_window_size(1024, 768, 1280, 720);
        assert_eq!((w, h), (960, 720));
        assert_eq!(w * 3, h * 4);
    }

    #[test]
    fn test_calculate_initial_window_size_21_9() {
        // Ultrawide 21:9 (2560x1080) ajustado para max 1280x720 sem distorção
        let (w, h) = ScreenViewer::calculate_initial_window_size(2560, 1080, 1280, 720);
        assert_eq!((w, h), (1280, 540));
        let ratio = w as f32 / h as f32;
        let expected = 2560.0 / 1080.0;
        assert!((ratio - expected).abs() < 0.01);
    }

    #[test]
    fn test_calculate_initial_window_size_portrait_9_16() {
        // Celular ou tela vertical 9:16 (1080x1920) ajustado para caber em 1280x720
        let (w, h) = ScreenViewer::calculate_initial_window_size(1080, 1920, 1280, 720);
        assert_eq!((w, h), (405, 720));
        assert_eq!(w * 16, h * 9);
    }

    #[test]
    fn test_calculate_initial_window_size_native_fits() {
        // Resolução 4:3 média (800x600) que já cabe no teto 1280x720
        let (w, h) = ScreenViewer::calculate_initial_window_size(800, 600, 1280, 720);
        assert_eq!((w, h), (800, 600));
    }

    #[test]
    fn test_calculate_initial_window_size_zeros_default() {
        // Valores 0 usam defaults confortáveis
        let (w, h) = ScreenViewer::calculate_initial_window_size(1920, 1080, 0, 0);
        assert_eq!((w, h), (1280, 720));

        let (w_fallback, h_fallback) = ScreenViewer::calculate_initial_window_size(0, 0, 0, 0);
        assert_eq!((w_fallback, h_fallback), (1280, 720));
    }
}
