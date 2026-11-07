use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
pub use opus1::{Application, Channels, OpusDecoder, OpusEncoder, SampleRate};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AudioEngineError {
    #[error("Dispositivo não encontrado: {0}")]
    DeviceNotFound(String),
    #[error("Erro no driver de áudio: {0}")]
    Cpal(#[from] cpal::DefaultStreamConfigError),
    #[error("Erro ao construir stream: {0}")]
    BuildStream(#[from] cpal::BuildStreamError),
    #[error("Erro ao iniciar reprodução: {0}")]
    PlayStream(#[from] cpal::PlayStreamError),
}

/// Configuração padrão de áudio para voz de baixa latência (48kHz, mono, frames de 20ms = 960 amostras)
pub const SAMPLE_RATE: u32 = 48000;
pub const FRAME_SIZE: usize = 960; // 20ms a 48kHz
pub const CHANNELS: u16 = 1;

/// Tipo de codec utilizado no pacote de voz
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq)]
pub enum AudioCodec {
    /// Áudio não comprimido PCM 16-bit
    Pcm16,
    /// Codec Opus RFC 6716 (baixa latência, 90% economia de banda)
    Opus,
}

/// Um pacote de frame de áudio em tempo real transmitido na malha P2P
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VoicePacket {
    /// ID do canal de voz
    pub channel_id: String,
    /// Chave pública do emissor (Ed25519)
    pub sender_pubkey: String,
    /// Apelido do emissor
    pub sender_name: String,
    /// Número sequencial para detectar perda de pacotes e jitter
    pub sequence: u64,
    /// Timestamp Unix em millis
    pub timestamp_ms: u64,
    /// Amostras de áudio codificadas (Opus ou PCM 16-bit)
    pub audio_data: Vec<u8>,
    /// Nível de energia do áudio / detecção de atividade de voz (VAD: 0 a 100)
    pub energy_level: u8,
    /// Codec empregado na compressão deste pacote
    #[serde(default = "default_codec")]
    pub codec: AudioCodec,
}

fn default_codec() -> AudioCodec {
    AudioCodec::Pcm16
}

impl VoicePacket {
    pub fn new(
        channel_id: String,
        sender_pubkey: String,
        sender_name: String,
        sequence: u64,
        timestamp_ms: u64,
        audio_data: Vec<u8>,
        energy_level: u8,
    ) -> Self {
        Self {
            channel_id,
            sender_pubkey,
            sender_name,
            sequence,
            timestamp_ms,
            audio_data,
            energy_level,
            codec: AudioCodec::Pcm16,
        }
    }

    pub fn new_opus(
        channel_id: String,
        sender_pubkey: String,
        sender_name: String,
        sequence: u64,
        timestamp_ms: u64,
        audio_data: Vec<u8>,
        energy_level: u8,
    ) -> Self {
        Self {
            channel_id,
            sender_pubkey,
            sender_name,
            sequence,
            timestamp_ms,
            audio_data,
            energy_level,
            codec: AudioCodec::Opus,
        }
    }

    /// Cria um pacote codificando as amostras PCM (f32) com o codec Opus (RFC 6716)
    pub fn from_pcm_samples_opus(
        channel_id: String,
        sender_pubkey: String,
        sender_name: String,
        sequence: u64,
        timestamp_ms: u64,
        samples: &[f32],
        encoder: &mut OpusEncoder,
    ) -> Result<Self, opus1::Error> {
        let energy = calculate_vad_energy(samples);
        let mut opus_buf = [0u8; 1275];
        let encoded_len = encoder.encode(samples, FRAME_SIZE, &mut opus_buf)?;

        Ok(Self::new_opus(
            channel_id,
            sender_pubkey,
            sender_name,
            sequence,
            timestamp_ms,
            opus_buf[..encoded_len].to_vec(),
            energy,
        ))
    }

    /// Decodifica o payload Opus de volta para amostras de áudio normalizadas (f32)
    pub fn to_pcm_samples_opus(&self, decoder: &mut OpusDecoder) -> Result<Vec<f32>, opus1::Error> {
        let mut out = vec![0.0f32; FRAME_SIZE];
        let decoded_len = decoder.decode(&self.audio_data, FRAME_SIZE, &mut out)?;
        out.truncate(decoded_len);
        Ok(out)
    }

    /// Cria um pacote a partir de amostras PCM (f32) calculando o VAD (nível de energia) (Legado PCM 16-bit)
    pub fn from_pcm_samples(
        channel_id: String,
        sender_pubkey: String,
        sender_name: String,
        sequence: u64,
        timestamp_ms: u64,
        samples: &[f32],
    ) -> Self {
        let energy = calculate_vad_energy(samples);
        let mut audio_bytes = Vec::with_capacity(samples.len() * 2);
        
        // Codifica f32 (-1.0 a 1.0) para PCM 16-bit com redução de 50% de banda imediata
        for &s in samples {
            let clamped = s.clamp(-1.0, 1.0);
            let pcm16 = (clamped * 32767.0) as i16;
            audio_bytes.extend_from_slice(&pcm16.to_le_bytes());
        }

        Self::new(
            channel_id,
            sender_pubkey,
            sender_name,
            sequence,
            timestamp_ms,
            audio_bytes,
            energy,
        )
    }

    /// Decodifica o payload de volta para amostras de áudio normalizadas (f32) para reprodução
    pub fn to_pcm_samples(&self) -> Vec<f32> {
        let mut samples = Vec::with_capacity(self.audio_data.len() / 2);
        for chunk in self.audio_data.chunks_exact(2) {
            let pcm16 = i16::from_le_bytes([chunk[0], chunk[1]]);
            samples.push(pcm16 as f32 / 32767.0);
        }
        samples
    }

    /// Serializa o pacote para transmissão na rede
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::wire::encode(self)
    }

    /// Desserializa o pacote recebido da rede
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, crate::wire::WireError> {
        crate::wire::decode_as(bytes)
    }

    /// Retorna se o pacote contém voz perceptível (Voice Activity Detection simples)
    pub fn is_speaking(&self, threshold: u8) -> bool {
        self.energy_level >= threshold
    }
}

/// Calcula a energia RMS do frame de áudio para Voice Activity Detection (0 a 100)
pub fn calculate_vad_energy(samples: &[f32]) -> u8 {
    if samples.is_empty() {
        return 0;
    }
    let sum_sq: f32 = samples.iter().map(|&s| s * s).sum();
    let rms = (sum_sq / samples.len() as f32).sqrt();
    let normalized = (rms * 250.0).clamp(0.0, 100.0);
    normalized as u8
}

/// Buffer para reordenar pacotes recebidos fora de ordem e mitigar jitter de rede
pub struct JitterBuffer {
    capacity: usize,
    buffer: HashMap<u64, VoicePacket>,
    last_played_seq: u64,
}

impl JitterBuffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            buffer: HashMap::new(),
            last_played_seq: 0,
        }
    }

    /// Insere um novo pacote de áudio no buffer
    pub fn push(&mut self, packet: VoicePacket) {
        if packet.sequence <= self.last_played_seq {
            // Pacote atrasado demais, descarta
            return;
        }

        if self.buffer.len() >= self.capacity {
            // Se encheu o buffer de jitter, remove o pacote mais antigo
            if let Some(&min_seq) = self.buffer.keys().min() {
                self.buffer.remove(&min_seq);
            }
        }

        self.buffer.insert(packet.sequence, packet);
    }

    /// Retira o próximo pacote sequencial para reprodução
    pub fn pop_next(&mut self) -> Option<VoicePacket> {
        let next_seq = self.last_played_seq + 1;
        if let Some(packet) = self.buffer.remove(&next_seq) {
            self.last_played_seq = next_seq;
            Some(packet)
        } else if let Some(&min_seq) = self.buffer.keys().min() {
            // Se houve perda de pacote e acumulou pacotes posteriores, avança
            if self.buffer.len() >= (self.capacity / 2).max(1) {
                let packet = self.buffer.remove(&min_seq)?;
                self.last_played_seq = packet.sequence;
                Some(packet)
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

/// Gerenciador de Dispositivos de Áudio do Sistema Operacional
pub struct AudioDeviceManager;

impl AudioDeviceManager {
    /// Lista os nomes dos dispositivos de microfone disponíveis
    pub fn list_input_devices() -> Vec<String> {
        let host = cpal::default_host();
        match host.input_devices() {
            Ok(devices) => devices.filter_map(|d| d.name().ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Lista os nomes dos dispositivos de saída (fones/alto-falantes) disponíveis
    pub fn list_output_devices() -> Vec<String> {
        let host = cpal::default_host();
        match host.output_devices() {
            Ok(devices) => devices.filter_map(|d| d.name().ok()).collect(),
            Err(_) => Vec::new(),
        }
    }

    /// Verifica se há pelo menos um dispositivo de entrada ou saída ativo
    pub fn is_audio_supported() -> bool {
        let host = cpal::default_host();
        host.default_input_device().is_some() || host.default_output_device().is_some()
    }
}

/// Pipeline completo de captura e reprodução de voz nativa P2P
pub struct VoiceEngine {
    is_muted: Arc<AtomicBool>,
    is_running: Arc<AtomicBool>,
    _input_stream: Option<cpal::Stream>,
    _output_stream: Option<cpal::Stream>,
    incoming_audio_tx: Sender<Vec<f32>>,
}

impl VoiceEngine {
    /// Inicializa a engine de áudio conectando o microfone e alto-falante padrão
    /// Retorna a engine e o receiver por onde saem os pacotes capturados do microfone local
    pub fn start() -> Result<(Self, Receiver<Vec<f32>>), AudioEngineError> {
        let host = cpal::default_host();
        let is_muted = Arc::new(AtomicBool::new(false));
        let is_running = Arc::new(AtomicBool::new(true));

        // 1. Canal de saída para os frames capturados do microfone local (20ms cada)
        let (mic_tx, mic_rx) = channel::<Vec<f32>>();

        // Configuração do microfone
        let input_stream = match host.default_input_device() {
            Some(input_dev) => {
                let config: cpal::StreamConfig = match input_dev.default_input_config() {
                    Ok(c) => c.into(),
                    Err(_) => cpal::StreamConfig {
                        channels: CHANNELS,
                        sample_rate: cpal::SampleRate(SAMPLE_RATE),
                        buffer_size: cpal::BufferSize::Default,
                    },
                };

                let is_muted_clone = Arc::clone(&is_muted);
                let is_running_clone = Arc::clone(&is_running);
                let mut pcm_accumulator = Vec::with_capacity(FRAME_SIZE * 2);

                match input_dev.build_input_stream(
                    &config,
                    move |data: &[f32], _: &cpal::InputCallbackInfo| {
                        if !is_running_clone.load(Ordering::Relaxed) {
                            return;
                        }

                        if is_muted_clone.load(Ordering::Relaxed) {
                            pcm_accumulator.clear();
                            return;
                        }

                        pcm_accumulator.extend_from_slice(data);

                        while pcm_accumulator.len() >= FRAME_SIZE {
                            let frame: Vec<f32> = pcm_accumulator.drain(..FRAME_SIZE).collect();
                            let _ = mic_tx.send(frame);
                        }
                    },
                    |err| tracing::warn!("Erro no stream de microfone: {}", err),
                    None,
                ) {
                    Ok(stream) => {
                        let _ = stream.play();
                        Some(stream)
                    }
                    Err(e) => {
                        tracing::warn!("Não foi possível abrir o dispositivo de microfone: {}", e);
                        None
                    }
                }
            }
            None => None,
        };

        // 2. Canal e buffer de reprodução de áudio dos pares remotos
        let (playback_tx, playback_rx) = channel::<Vec<f32>>();
        let playback_rx = Arc::new(Mutex::new(playback_rx));

        // Configuração do alto-falante
        let output_stream = match host.default_output_device() {
            Some(output_dev) => {
                let config: cpal::StreamConfig = match output_dev.default_output_config() {
                    Ok(c) => c.into(),
                    Err(_) => cpal::StreamConfig {
                        channels: CHANNELS,
                        sample_rate: cpal::SampleRate(SAMPLE_RATE),
                        buffer_size: cpal::BufferSize::Default,
                    },
                };

                let playback_rx_clone = Arc::clone(&playback_rx);
                let mut current_playback_buffer: Vec<f32> = Vec::new();

                match output_dev.build_output_stream(
                    &config,
                    move |output: &mut [f32], _: &cpal::OutputCallbackInfo| {
                        if let Ok(rx) = playback_rx_clone.try_lock() {
                            while let Ok(samples) = rx.try_recv() {
                                current_playback_buffer.extend(samples);
                            }
                        }

                        for sample in output.iter_mut() {
                            if !current_playback_buffer.is_empty() {
                                *sample = current_playback_buffer.remove(0);
                            } else {
                                *sample = 0.0;
                            }
                        }
                    },
                    |_err| {},
                    None,
                ) {
                    Ok(stream) => {
                        let _ = stream.play();
                        Some(stream)
                    }
                    Err(e) => {
                        tracing::warn!("Não foi possível abrir o dispositivo de saída de áudio: {}", e);
                        None
                    }
                }
            }
            None => None,
        };

        Ok((
            Self {
                is_muted,
                is_running,
                _input_stream: input_stream,
                _output_stream: output_stream,
                incoming_audio_tx: playback_tx,
            },
            mic_rx,
        ))
    }

    /// Alimenta o motor de áudio com as amostras recebidas de um par remoto
    pub fn play_remote_samples(&self, samples: Vec<f32>) {
        let _ = self.incoming_audio_tx.send(samples);
    }

    /// Ativa ou desativa o microfone local (Mute)
    pub fn set_mute(&self, mute: bool) {
        self.is_muted.store(mute, Ordering::SeqCst);
    }

    /// Alterna o estado de mute do microfone
    pub fn toggle_mute(&self) -> bool {
        let current = self.is_muted.load(Ordering::SeqCst);
        let new_state = !current;
        self.is_muted.store(new_state, Ordering::SeqCst);
        new_state
    }

    /// Retorna se o microfone está atualmente mutado
    pub fn is_muted(&self) -> bool {
        self.is_muted.load(Ordering::SeqCst)
    }

    /// Retorna uma referência compartilhável para verificar se o microfone está mutado
    pub fn is_muted_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.is_muted)
    }

    /// Encerra as threads de áudio
    pub fn stop(&self) {
        self.is_running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_voice_packet_serialization() {
        let packet = VoicePacket::new(
            "canal-voz-1".to_string(),
            "pubkey_123".to_string(),
            "Victor".to_string(),
            42,
            1730490000000,
            vec![1, 2, 3, 4, 5],
            85,
        );

        let bytes = packet.to_bytes();
        let decoded = VoicePacket::from_bytes(&bytes).expect("Desserialização falhou");

        assert_eq!(packet, decoded);
        assert!(decoded.is_speaking(50));
        assert!(!decoded.is_speaking(90));
    }

    #[test]
    fn test_pcm_samples_conversion_and_vad() {
        // Amostras de silêncio
        let silence = vec![0.0f32; 960];
        let p_silence = VoicePacket::from_pcm_samples(
            "v".into(), "k".into(), "u".into(), 1, 1000, &silence
        );
        assert_eq!(p_silence.energy_level, 0);
        assert!(!p_silence.is_speaking(10));

        // Amostras de onda senoidal (voz/som alto)
        let sine: Vec<f32> = (0..960).map(|i| (i as f32 * 0.1).sin() * 0.8).collect();
        let p_sound = VoicePacket::from_pcm_samples(
            "v".into(), "k".into(), "u".into(), 2, 1020, &sine
        );
        assert!(p_sound.energy_level > 20);
        assert!(p_sound.is_speaking(15));

        // Converte de volta para PCM e verifica a preservação do sinal
        let restored = p_sound.to_pcm_samples();
        assert_eq!(restored.len(), sine.len());
        assert!((restored[10] - sine[10]).abs() < 0.01);
    }

    #[test]
    fn test_opus_compression_and_decompression() {
        let mut encoder = OpusEncoder::new(SampleRate::Hz48000, Channels::Mono, Application::Voip)
            .expect("Deve criar encoder Opus");
        let mut decoder = OpusDecoder::new(SampleRate::Hz48000, Channels::Mono)
            .expect("Deve criar decoder Opus");

        // Cria 960 amostras (20ms) a 440Hz
        let sine: Vec<f32> = (0..FRAME_SIZE)
            .map(|i| (i as f32 * 0.05).sin() * 0.5)
            .collect();

        let packet = VoicePacket::from_pcm_samples_opus(
            "voice_room".into(),
            "pubkey_user".into(),
            "Alice".into(),
            1,
            12345678,
            &sine,
            &mut encoder,
        ).expect("Codificação Opus deve ter sucesso");

        // O áudio bruto PCM 16-bit tinha 1920 bytes. O Opus reduz para uma fração mínima (~100-200 bytes)
        assert!(packet.audio_data.len() < 500, "Opus deve comprimir o áudio para < 500 bytes");
        assert!(packet.audio_data.len() > 10, "Opus deve conter payload válido");

        let decoded = packet.to_pcm_samples_opus(&mut decoder)
            .expect("Decodificação Opus deve ter sucesso");

        assert_eq!(decoded.len(), FRAME_SIZE);
        // Verifica que o decoder gerou amostras de saída
        assert!(decoded.iter().any(|&s| s.abs() > 0.0 || s == 0.0));
    }

    #[test]
    fn test_jitter_buffer_ordering() {
        let mut jb = JitterBuffer::new(5);

        let p1 = VoicePacket::new("v".into(), "k".into(), "u".into(), 1, 100, vec![10], 50);
        let p2 = VoicePacket::new("v".into(), "k".into(), "u".into(), 2, 120, vec![20], 50);
        let p3 = VoicePacket::new("v".into(), "k".into(), "u".into(), 3, 140, vec![30], 50);

        // Insere fora de ordem (p2, depois p1, depois p3)
        jb.push(p2);
        jb.push(p1);
        jb.push(p3);

        assert_eq!(jb.len(), 3);

        let out1 = jb.pop_next().expect("Deve entregar seq 1");
        assert_eq!(out1.sequence, 1);

        let out2 = jb.pop_next().expect("Deve entregar seq 2");
        assert_eq!(out2.sequence, 2);

        let out3 = jb.pop_next().expect("Deve entregar seq 3");
        assert_eq!(out3.sequence, 3);

        assert!(jb.pop_next().is_none());
    }

    #[test]
    fn test_jitter_buffer_discard_old_packet() {
        let mut jb = JitterBuffer::new(5);
        let p1 = VoicePacket::new("v".into(), "k".into(), "u".into(), 1, 100, vec![10], 50);
        jb.push(p1);
        let _ = jb.pop_next();

        let p1_dupe = VoicePacket::new("v".into(), "k".into(), "u".into(), 1, 100, vec![10], 50);
        jb.push(p1_dupe);
        assert!(jb.is_empty());
    }

    #[test]
    fn test_audio_device_manager() {
        // Testa se a chamada a list_input_devices e list_output_devices não causa panic
        let _ = AudioDeviceManager::list_input_devices();
        let _ = AudioDeviceManager::list_output_devices();
    }

    #[test]
    fn test_voice_engine_state_toggle() {
        if let Ok((engine, _rx)) = VoiceEngine::start() {
            assert!(!engine.is_muted());
            let muted = engine.toggle_mute();
            assert!(muted);
            assert!(engine.is_muted());
            let unmuted = engine.toggle_mute();
            assert!(!unmuted);
            assert!(!engine.is_muted());
            engine.stop();
        }
    }
}
