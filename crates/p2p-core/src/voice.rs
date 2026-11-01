use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Um pacote de frame de áudio em tempo real (20ms) transmitido na rede P2P
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
    /// Payload de áudio (Opus comprimido ou PCM codificado)
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

    /// Serializa o pacote para transmissão direta em datagramas QUIC/UDP ou GossipSub
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

        // Pop deve entregar ordenado seq 1, 2, 3
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
        let _ = jb.pop_next(); // Consumiu seq 1

        // Tentar reinserir seq 1 ou pacote anterior deve ser ignorado
        let p1_dupe = VoicePacket::new("v".into(), "k".into(), "u".into(), 1, 100, vec![10], 50);
        jb.push(p1_dupe);
        assert!(jb.is_empty());
    }
}
