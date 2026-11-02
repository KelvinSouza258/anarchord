//! Janela temporária com animação contínua a 60 FPS, para medir a captura de tela com movimento real.
//! Modo padrão: conteúdo típico de tela (fundo fixo, "texto" rolando e uma janela se movendo).
//! Modo "noise": todos os pixels mudam a cada frame (pior caso para o encoder).
use minifb::{Window, WindowOptions};
use std::time::{Duration, Instant};

fn main() {
    let secs: u64 = std::env::args().nth(1).and_then(|s| s.parse().ok()).unwrap_or(15);
    let noise = std::env::args().nth(2).as_deref() == Some("noise");
    let (w, h) = (1920usize, 1080usize);
    let mut window = Window::new("Anarchord - teste de movimento", w, h, WindowOptions { borderless: true, ..WindowOptions::default() })
        .expect("janela");
    window.set_position(0, 0);
    window.set_target_fps(60);

    // Fundo fixo em gradiente e uma "página de texto" (linhas de blocos) que vai rolar
    let background: Vec<u32> = (0..w * h).map(|i| { let (x, y) = (i % w, i / w); ((x * 60 / w) as u32) << 16 | ((y * 80 / h) as u32) << 8 | 0x30 }).collect();
    let page_h = h * 3;
    let page: Vec<u32> = (0..900 * page_h).map(|i| {
        let (x, y) = (i % 900, i / 900);
        let line = y / 22;
        let in_glyph = y % 22 < 14 && (x / 9 + line * 7) % 11 != 0 && x < 820 - (line * 37 % 300);
        if in_glyph { 0x202020 } else { 0xf4f4f4 }
    }).collect();

    let mut buf = vec![0u32; w * h];
    let start = Instant::now();
    let mut t = 0usize;
    while window.is_open() && start.elapsed() < Duration::from_secs(secs) {
        if noise {
            for y in 0..h { for x in 0..w {
                let v = ((x + t * 7) ^ (y + t * 3)) as u32;
                buf[y * w + x] = (v & 0xff) << 16 | ((v >> 2) & 0xff) << 8 | ((x + y + t) as u32 & 0xff);
            }}
        } else {
            buf.copy_from_slice(&background);
            // Página rolando 6 px por frame à esquerda
            let scroll = (t * 6) % (page_h - h);
            for y in 0..h - 100 {
                let src = (y + scroll) * 900;
                buf[(y + 50) * w + 100..(y + 50) * w + 1000].copy_from_slice(&page[src..src + 900]);
            }
            // "Janela" de 500x350 se movendo à direita
            let (wx, wy) = (1100 + (t * 5) % 300, 200 + (t * 3) % 400);
            for y in wy..wy + 350 { for x in wx..wx + 500 {
                buf[y * w + x] = if y < wy + 30 { 0x3355aa } else { 0xdddddd ^ (((x - wx) / 40 + (y - wy) / 40) as u32 & 1) * 0x111111 };
            }}
        }
        window.update_with_buffer(&buf, w, h).unwrap();
        t += 1;
    }
}
