use minifb::{Key, Window, WindowOptions};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;
use openh264::nal_units;
use p2p_core::screen::VideoCodec;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Exibidor gráfico de tela em janela nativa ultraleve via minifb com métricas de telemetria em tempo real
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
                    eprintln!("Erro ao abrir janela de vídeo: {:?}", e);
                    is_active.store(false, Ordering::SeqCst);
                    return;
                }
            };

            window.set_target_fps(60);

            let mut current_buffer: Vec<u32> = vec![0; initial_width * initial_height];
            let mut curr_w = initial_width;
            let mut curr_h = initial_height;

            let mut h264_decoder = Decoder::new().ok();
            let mut rgba_staging: Vec<u8> = Vec::new();

            // Variáveis de telemetria (FPS e velocidade de rede)
            let mut last_metrics_update = Instant::now();
            let mut frames_this_second = 0u32;
            let mut bytes_this_second = 0usize;
            let mut total_bytes_received = 0u64;
            let mut current_fps = 0u32;
            let mut current_kbps = 0.0f32;
            let mut current_codec_name = "H.264";

            while window.is_open() && !window.is_key_down(Key::Escape) && is_active.load(Ordering::Relaxed) {
                let mut incoming_packets = Vec::new();
                if let Ok(rx) = rx_video_frames.lock() {
                    while let Ok(pkt) = rx.try_recv() {
                        incoming_packets.push(pkt);
                    }
                }

                for (codec, data) in incoming_packets {
                    let data_len = data.len();
                    bytes_this_second += data_len;
                    total_bytes_received += data_len as u64;

                    match codec {
                        VideoCodec::H264 => {
                            current_codec_name = "H.264";
                            if let Some(ref mut decoder) = h264_decoder {
                                let mut rendered = false;
                                if let Ok(Some(yuv)) = decoder.decode(&data) {
                                    Self::render_yuv_to_buffer(&yuv, &mut rgba_staging, &mut current_buffer, &mut curr_w, &mut curr_h);
                                    rendered = true;
                                } else {
                                    for packet in nal_units(&data) {
                                        if let Ok(Some(yuv)) = decoder.decode(packet) {
                                            Self::render_yuv_to_buffer(&yuv, &mut rgba_staging, &mut current_buffer, &mut curr_w, &mut curr_h);
                                            rendered = true;
                                        }
                                    }
                                }

                                if rendered {
                                    frames_this_second += 1;
                                }
                            }
                        }
                        VideoCodec::Jpeg => {
                            current_codec_name = "JPEG";
                            if let Ok(img) = image::load_from_memory_with_format(&data, image::ImageFormat::Jpeg) {
                                let rgba = img.to_rgba8();
                                let (w, h) = (rgba.width() as usize, rgba.height() as usize);

                                if w != curr_w || h != curr_h {
                                    curr_w = w;
                                    curr_h = h;
                                    current_buffer.resize(curr_w * curr_h, 0);
                                }

                                for (i, pixel) in rgba.chunks_exact(4).enumerate() {
                                    if i < current_buffer.len() {
                                        let r = pixel[0] as u32;
                                        let g = pixel[1] as u32;
                                        let b = pixel[2] as u32;
                                        current_buffer[i] = (r << 16) | (g << 8) | b;
                                    }
                                }
                                frames_this_second += 1;
                            }
                        }
                    }
                }

                // Atualiza a barra de título com estatísticas a cada 500ms
                if last_metrics_update.elapsed() >= Duration::from_millis(500) {
                    let elapsed_sec = last_metrics_update.elapsed().as_secs_f32();
                    current_fps = (frames_this_second as f32 / elapsed_sec).round() as u32;
                    current_kbps = (bytes_this_second as f32 / 1024.0) / elapsed_sec;

                    let total_mb = (total_bytes_received as f64) / (1024.0 * 1024.0);

                    window.set_title(&format!(
                        "📺 [{}] {} | {}x{} | {} FPS | {:.1} KB/s ({:.2} MB) | ESC para fechar",
                        current_codec_name, title, curr_w, curr_h, current_fps, current_kbps, total_mb
                    ));

                    frames_this_second = 0;
                    bytes_this_second = 0;
                    last_metrics_update = Instant::now();
                }

                if let Err(_) = window.update_with_buffer(&current_buffer, curr_w, curr_h) {
                    break;
                }

                std::thread::sleep(Duration::from_millis(5));
            }

            is_active.store(false, Ordering::SeqCst);
        });
    }

    fn render_yuv_to_buffer(
        yuv: &openh264::decoder::DecodedYUV<'_>,
        rgba_staging: &mut Vec<u8>,
        current_buffer: &mut Vec<u32>,
        curr_w: &mut usize,
        curr_h: &mut usize,
    ) {
        let dim = yuv.dimensions();
        let (w, h) = (dim.0, dim.1);
        let required_len = w * h * 4;

        if rgba_staging.len() != required_len {
            rgba_staging.resize(required_len, 0);
        }

        yuv.write_rgba8(rgba_staging);

        if w != *curr_w || h != *curr_h {
            *curr_w = w;
            *curr_h = h;
            current_buffer.resize(*curr_w * *curr_h, 0);
        }

        for (i, pixel) in rgba_staging.chunks_exact(4).enumerate() {
            if i < current_buffer.len() {
                let r = pixel[0] as u32;
                let g = pixel[1] as u32;
                let b = pixel[2] as u32;
                current_buffer[i] = (r << 16) | (g << 8) | b;
            }
        }
    }
}
