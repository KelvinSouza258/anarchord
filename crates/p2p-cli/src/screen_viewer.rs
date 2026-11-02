use minifb::{Key, Window, WindowOptions};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::Receiver;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Exibidor gráfico de tela em janela nativa ultraleve via minifb
pub struct ScreenViewer;

impl ScreenViewer {
    /// Abre uma janela nativa independente e renderiza os quadros JPEG recebidos em tempo real.
    /// Fecha com tecla ESC ou se o usuário clicar no 'X' da janela.
    pub fn spawn_window(
        title: String,
        mut initial_width: usize,
        mut initial_height: usize,
        rx_jpeg_frames: Arc<Mutex<Receiver<Vec<u8>>>>,
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
                &format!("📺 Anarchord Screen - {} (ESC para fechar)", title),
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

            while window.is_open() && !window.is_key_down(Key::Escape) && is_active.load(Ordering::Relaxed) {
                // Esvazia a fila para sempre renderizar o quadro mais recente (evita atraso/lag)
                let mut latest_frame = None;
                if let Ok(rx) = rx_jpeg_frames.lock() {
                    while let Ok(frame_bytes) = rx.try_recv() {
                        latest_frame = Some(frame_bytes);
                    }
                }

                if let Some(jpeg_bytes) = latest_frame {
                    if let Ok(img) = image::load_from_memory_with_format(&jpeg_bytes, image::ImageFormat::Jpeg) {
                        let rgba = img.to_rgba8();
                        let (w, h) = (rgba.width() as usize, rgba.height() as usize);

                        if w != curr_w || h != curr_h {
                            curr_w = w;
                            curr_h = h;
                            current_buffer.resize(curr_w * curr_h, 0);
                        }

                        // Converte RGBA8 para o formato 0RGB exigido pelo minifb (0x00RRGGBB)
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

                if let Err(_) = window.update_with_buffer(&current_buffer, curr_w, curr_h) {
                    break;
                }

                std::thread::sleep(Duration::from_millis(10));
            }

            is_active.store(false, Ordering::SeqCst);
        });
    }
}
