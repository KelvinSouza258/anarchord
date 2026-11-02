//! Recepção de tela: decodificação H.264/JPEG para RGBA e controle de repasse por keyframe.
//! Independente de plataforma; quem exibe (janela nativa, GUI, mobile) só consome o RGBA.

use super::VideoCodec;
use openh264::decoder::Decoder;
use openh264::formats::YUVSource;
use openh264::nal_units;

/// Controla o repasse de quadros H.264 para um decodificador com fila limitada.
/// Um P-frame só decodifica se o anterior chegou; então, depois de um descarte (fila cheia),
/// nada é repassado até o próximo keyframe. Começa esperando um keyframe pelo mesmo motivo:
/// quem entra no meio da transmissão não consegue decodificar os P-frames antes dele.
#[derive(Debug)]
pub struct KeyframeGate {
    waiting_keyframe: bool,
}

impl Default for KeyframeGate {
    fn default() -> Self {
        Self { waiting_keyframe: true }
    }
}

impl KeyframeGate {
    pub fn new() -> Self {
        Self::default()
    }

    /// Tenta repassar um quadro com `try_send` (que devolve se coube na fila).
    /// Retorna se o quadro foi repassado.
    pub fn forward(&mut self, is_keyframe: bool, try_send: impl FnOnce() -> bool) -> bool {
        if self.waiting_keyframe && !is_keyframe {
            return false;
        }
        let sent = try_send();
        self.waiting_keyframe = !sent;
        sent
    }
}

/// Quadro decodificado em RGBA (4 bytes por pixel, sem padding)
#[derive(Debug, Default)]
pub struct DecodedFrame {
    pub width: usize,
    pub height: usize,
    pub rgba: Vec<u8>,
}

/// Decodificador de quadros de tela. Reaproveita o buffer RGBA entre quadros.
pub struct ScreenDecoder {
    h264: Option<Decoder>,
    frame: DecodedFrame,
}

impl Default for ScreenDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl ScreenDecoder {
    pub fn new() -> Self {
        Self { h264: Decoder::new().ok(), frame: DecodedFrame::default() }
    }

    /// Decodifica um quadro. Retorna `None` quando ele não gera imagem (ex.: P-frame sem a referência).
    pub fn decode(&mut self, codec: VideoCodec, data: &[u8]) -> Option<&DecodedFrame> {
        let decoded = match codec {
            VideoCodec::H264 => self.decode_h264(data),
            VideoCodec::Jpeg => self.decode_jpeg(data),
        };
        decoded.then_some(&self.frame)
    }

    fn decode_h264(&mut self, data: &[u8]) -> bool {
        let Some(decoder) = self.h264.as_mut() else { return false };
        let frame = &mut self.frame;
        let mut store = |yuv: &openh264::decoder::DecodedYUV<'_>| {
            let (w, h) = yuv.dimensions();
            frame.rgba.resize(w * h * 4, 0);
            yuv.write_rgba8(&mut frame.rgba);
            frame.width = w;
            frame.height = h;
        };

        let mut rendered = false;
        for nal in nal_units(data) {
            if let Ok(Some(yuv)) = decoder.decode(nal) {
                store(&yuv);
                rendered = true;
            }
        }
        // Alguns fluxos só produzem imagem quando o pacote inteiro é entregue de uma vez
        if !rendered {
            if let Ok(Some(yuv)) = decoder.decode(data) {
                store(&yuv);
                rendered = true;
            }
        }
        rendered
    }

    fn decode_jpeg(&mut self, data: &[u8]) -> bool {
        let Ok(img) = image::load_from_memory_with_format(data, image::ImageFormat::Jpeg) else { return false };
        let rgba = img.to_rgba8();
        self.frame.width = rgba.width() as usize;
        self.frame.height = rgba.height() as usize;
        self.frame.rgba = rgba.into_raw();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::screen::encoder::{synthetic_frame, FrameEncoder};

    #[test]
    fn test_keyframe_gate_waits_for_first_keyframe() {
        let mut gate = KeyframeGate::new();
        assert!(!gate.forward(false, || true), "P-frame antes do primeiro keyframe não decodifica");
        assert!(gate.forward(true, || true));
        assert!(gate.forward(false, || true));
    }

    #[test]
    fn test_keyframe_gate_resyncs_after_drop() {
        let mut gate = KeyframeGate::new();
        assert!(gate.forward(true, || true));
        assert!(!gate.forward(false, || false), "fila cheia: quadro descartado");
        assert!(!gate.forward(false, || panic!("não deve tentar enviar P-frame sem a referência")));
        assert!(gate.forward(true, || true), "keyframe ressincroniza");
        assert!(gate.forward(false, || true));
    }

    #[test]
    fn test_h264_roundtrip_preserves_dimensions_and_content() {
        let mut enc = FrameEncoder::new(30);
        let mut dec = ScreenDecoder::new();
        for seq in 0..3 {
            let src = synthetic_frame(seq);
            let packet = enc.encode(&src, "s", "pk", "Alice");
            let frame = dec.decode(packet.codec, &packet.video_data).expect("quadro deveria decodificar");
            assert_eq!((frame.width, frame.height), (640, 360));
            assert_eq!(frame.rgba.len(), 640 * 360 * 4);
            // Compressão com perdas: compara a média de brilho, não pixel a pixel
            let avg = |v: &[u8]| v.iter().step_by(4).map(|&b| b as u64).sum::<u64>() / (v.len() as u64 / 4);
            let (a, b) = (avg(&src.rgba), avg(&frame.rgba));
            assert!(a.abs_diff(b) < 12, "brilho médio divergiu demais: {} vs {}", a, b);
        }
    }

    #[test]
    fn test_garbage_does_not_produce_frame() {
        let mut dec = ScreenDecoder::new();
        assert!(dec.decode(VideoCodec::Jpeg, b"nao e jpeg").is_none());
        assert!(dec.decode(VideoCodec::H264, &[0, 0, 0, 1, 0x41, 0x9a]).is_none());
    }
}
