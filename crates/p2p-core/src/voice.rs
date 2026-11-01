use cpal::traits::{DeviceTrait, HostTrait};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Configuração padrão de áudio para voz de baixa latência (48kHz, mono, frames de 20ms = 960 amostras)
pub const SAMPLE_RATE: u32 = 48000;
pub const FRAME_SIZE: usize = 960; // 20ms a 48kHz
pub const CHANNELS: u16 = 1;

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
    /// Amostras de áudio PCM codificadas (f32 convertidos para bytes ou comprimidos)
    pub audio_data: Vec<u8>,
    /// Nível de energia do áudio / detecção de atividade de voz (VAD: 0 a 100)
    pub energy_level: u8,
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
        }
    }

    /// Cria um pacote a partir de amostras PCM (f32) calculando o VAD (nível de energia)
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
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// Desserializa o pacote recebido da rede
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
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

        let bytes = packet.to_bytes().expect("Serialização falhou");
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
}
