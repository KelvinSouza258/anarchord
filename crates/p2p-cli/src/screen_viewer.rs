use minifb::{Key, Window, WindowOptions};
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;
use openh264::nal_units;
use p2p_core::screen::VideoCodec;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Exibidor gráfico de tela em janela nativa ultraleve via minifb com decodificador H.264 em tempo real
pub struct ScreenViewer;

impl ScreenViewer {
    /// Abre uma janela nativa independente e renderiza os quadros H.264 (ou JPEG) recebidos em tempo real.
    /// Fecha com tecla ESC ou se o usuário clicar no 'X' da janela.
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
                &format!("📺 Anarchord Screen [H.264 HD] - {} (ESC para fechar)", title),
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

            while window.is_open() && !window.is_key_down(Key::Escape) && is_active.load(Ordering::Relaxed) {
                let mut incoming_packets = Vec::new();
                if let Ok(rx) = rx_video_frames.lock() {
                    while let Ok(pkt) = rx.try_recv() {
                        incoming_packets.push(pkt);
                    }
                }

                for (codec, data) in incoming_packets {
                    match codec {
                        VideoCodec::H264 => {
                            if let Some(ref mut decoder) = h264_decoder {
                                // 1. Tenta decodificar o bitstream direto
                                let decode_res = decoder.decode(&data);
                                match decode_res {
                                    Ok(Some(yuv)) => {
                                        Self::render_yuv_to_buffer(&yuv, &mut rgba_staging, &mut current_buffer, &mut curr_w, &mut curr_h);
                                    }
                                    _ => {
                                        // 2. Fallback: Se o bitstream veio com múltiplos NALs, itera por eles
                                        for packet in nal_units(&data) {
                                            if let Ok(Some(yuv)) = decoder.decode(packet) {
                                                Self::render_yuv_to_buffer(&yuv, &mut rgba_staging, &mut current_buffer, &mut curr_w, &mut curr_h);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        VideoCodec::Jpeg => {
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
                            }
                        }
                    }
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
