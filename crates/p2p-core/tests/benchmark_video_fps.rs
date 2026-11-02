use std::time::Instant;
use openh264::encoder::{Encoder, EncoderConfig};
use openh264::formats::{RgbaSliceU8, YUVBuffer};
use openh264::OpenH264API;

#[test]
fn test_video_pipeline_fps_performance_benchmark() {
    println!("\n=== BENCHMARK DE DESEMPENHO DO PIPELINE DE VÍDEO (TARGET >= 30 FPS) ===");

    let frames_to_test = 60; // 2 segundos simulados
    let (width, height) = (640u32, 360u32);

    // 1. Benchmark do codificador OpenH264
    let api = OpenH264API::from_source();
    let config = EncoderConfig::new();
    let mut encoder = Encoder::with_api_config(api, config)
        .expect("OpenH264 encoder deve inicializar com sucesso");

    let raw_frame = vec![128u8; (width * height * 4) as usize];
    let start_encode = Instant::now();

    for i in 0..frames_to_test {
        let rgba_src = RgbaSliceU8::new(&raw_frame, (width as usize, height as usize));
        let yuv = YUVBuffer::from_rgb_source(rgba_src);
        if i % 30 == 0 {
            encoder.force_intra_frame();
        }
        let stream = encoder.encode(&yuv).expect("Codificação H.264 deve suceder");
        assert!(!stream.to_vec().is_empty(), "Stream H.264 não pode ser vazia");
    }

    let encode_duration = start_encode.elapsed();
    let avg_ms_per_frame = encode_duration.as_secs_f64() * 1000.0 / (frames_to_test as f64);
    let calculated_fps = (frames_to_test as f64) / encode_duration.as_secs_f64();

    println!("Tempo total para {} frames: {:.2}s", frames_to_test, encode_duration.as_secs_f64());
    println!("Tempo médio por frame: {:.2} ms (Orçamento para 30 FPS: <= 33.3 ms)", avg_ms_per_frame);
    println!("FPS Teórico do Encoder: {:.1} FPS", calculated_fps);

    // VALIDAÇÃO E MÉTRICA OBRIGATÓRIA:
    // O pipeline deve ser capaz de codificar a no mínimo 30 FPS (<= 33.3ms por quadro)
    assert!(
        calculated_fps >= 30.0,
        "🚨 REJEITADO: Desempenho insuficiente do encoder H.264! Esperado >= 30.0 FPS, obtido: {:.1} FPS (tempo médio por frame: {:.2}ms)",
        calculated_fps,
        avg_ms_per_frame
    );
    assert!(
        avg_ms_per_frame <= 33.3,
        "🚨 REJEITADO: Tempo por frame acima do orçamento de 33.3ms: {:.2}ms",
        avg_ms_per_frame
    );

    println!("✅ APROVADO: Pipeline de codificação superou o target de 30 FPS com folga ({:.1} FPS)!\n", calculated_fps);
}
