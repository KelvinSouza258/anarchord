use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// Tamanho padrão de cada bloco de transferência P2P (64 KB)
pub const CHUNK_SIZE: usize = 64 * 1024;

/// Proposta de envio direto de arquivo (oferta P2P)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileOffer {
    /// ID único da transferência (hash SHA-256 do arquivo completo)
    pub file_hash: String,
    /// Nome original do arquivo (sem caminhos de diretório)
    pub file_name: String,
    /// Tamanho total em bytes
    pub file_size: u64,
    /// Total de chunks de 64KB necessários
    pub total_chunks: u32,
    /// Chave pública Ed25519 do remetente
    pub sender_pubkey: String,
    /// Nome/Apelido do remetente
    pub sender_name: String,
    /// Chave pública Ed25519 do destinatário pretendido
    pub recipient_pubkey: String,
}

/// Resposta do destinatário aceitando ou rejeitando a oferta de arquivo
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileDecision {
    pub file_hash: String,
    pub accepted: bool,
    pub responder_pubkey: String,
}

/// Um bloco individual do arquivo transmitido diretamente entre os pares
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct FileChunk {
    pub file_hash: String,
    pub chunk_index: u32,
    pub total_chunks: u32,
    pub data: Vec<u8>,
}

/// Mensagem unificada de transferência direta de arquivos na malha P2P
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum FileTransferMessage {
    /// Oferta enviada do Remetente -> Destinatário
    Offer(FileOffer),
    /// Decisão enviada do Destinatário -> Remetente (Aceite / Rejeição)
    Decision(FileDecision),
    /// Chunks de dados enviados do Remetente -> Destinatário
    Chunk(FileChunk),
}

impl FileTransferMessage {
    pub fn to_bytes(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

/// Montador e reconstrutor de arquivos recebidos em chunks
#[derive(Debug, Clone)]
pub struct FileReceiver {
    pub file_name: String,
    pub file_size: u64,
    pub total_chunks: u32,
    pub received_chunks: HashMap<u32, Vec<u8>>,
}

impl FileReceiver {
    pub fn new(file_name: String, file_size: u64, total_chunks: u32) -> Self {
        Self {
            file_name,
            file_size,
            total_chunks,
            received_chunks: HashMap::new(),
        }
    }

    /// Adiciona um pedaço recebido e retorna o progresso atual em porcentagem (0.0 a 100.0)
    pub fn add_chunk(&mut self, chunk_index: u32, data: Vec<u8>) -> f32 {
        self.received_chunks.insert(chunk_index, data);
        (self.received_chunks.len() as f32 / self.total_chunks as f32) * 100.0
    }

    /// Retorna verdadeiro se todos os chunks foram recebidos
    pub fn is_complete(&self) -> bool {
        self.received_chunks.len() == self.total_chunks as usize
    }

    /// Reconstitui os bytes na ordem correta e valida contra o hash SHA-256 esperado
    pub fn assemble_and_verify(&self, expected_sha256: &str) -> Result<Vec<u8>, &'static str> {
        if !self.is_complete() {
            return Err("Nem todos os blocos foram recebidos ainda");
        }

        let mut full_bytes = Vec::with_capacity(self.file_size as usize);
        for i in 0..self.total_chunks {
            if let Some(chunk_data) = self.received_chunks.get(&i) {
                full_bytes.extend_from_slice(chunk_data);
            } else {
                return Err("Bloco faltante na sequência");
            }
        }

        let actual_hash = calculate_file_hash(&full_bytes);
        if actual_hash != expected_sha256 {
            return Err("Checksum SHA-256 incorreto; arquivo corrompido");
        }

        Ok(full_bytes)
    }
}

/// Utilitário para fatiar um arquivo em memória em chunks de 64KB prontos para envio
pub fn chunk_file(file_hash: &str, data: &[u8]) -> Vec<FileChunk> {
    let chunks: Vec<&[u8]> = data.chunks(CHUNK_SIZE).collect();
    let total_chunks = chunks.len() as u32;

    chunks
        .into_iter()
        .enumerate()
        .map(|(index, chunk_slice)| FileChunk {
            file_hash: file_hash.to_string(),
            chunk_index: index as u32,
            total_chunks,
            data: chunk_slice.to_vec(),
        })
        .collect()
}

/// Calcula a assinatura SHA-256 em hexadecimal de um arquivo / buffer
pub fn calculate_file_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_chunking_and_reassembly() {
        // Gera um arquivo simulado de 150 KB (deve gerar 3 chunks de 64KB)
        let file_data = vec![0x42u8; 150 * 1024];
        let file_hash = calculate_file_hash(&file_data);

        let chunks = chunk_file(&file_hash, &file_data);
        assert_eq!(chunks.len(), 3);
        assert_eq!(chunks[0].chunk_index, 0);
        assert_eq!(chunks[0].data.len(), 64 * 1024);
        assert_eq!(chunks[1].chunk_index, 1);
        assert_eq!(chunks[1].data.len(), 64 * 1024);
        assert_eq!(chunks[2].chunk_index, 2);
        assert_eq!(chunks[2].data.len(), 22 * 1024);

        // Receptor monta o arquivo
        let mut receiver = FileReceiver::new("teste.png".into(), file_data.len() as u64, chunks.len() as u32);
        assert!(!receiver.is_complete());

        // Recebe pedaços (inclusive fora de ordem)
        receiver.add_chunk(chunks[1].chunk_index, chunks[1].data.clone());
        receiver.add_chunk(chunks[0].chunk_index, chunks[0].data.clone());
        receiver.add_chunk(chunks[2].chunk_index, chunks[2].data.clone());

        assert!(receiver.is_complete());
        let assembled = receiver.assemble_and_verify(&file_hash).expect("Deve montar e validar hash");
        assert_eq!(assembled, file_data);
    }

    #[test]
    fn test_corrupted_reassembly_fails() {
        let file_data = b"conteudo de arquivo original secreto";
        let file_hash = calculate_file_hash(file_data);

        let mut receiver = FileReceiver::new("doc.txt".into(), file_data.len() as u64, 1);
        receiver.add_chunk(0, b"conteudo adulterado".to_vec());

        assert!(receiver.is_complete());
        let result = receiver.assemble_and_verify(&file_hash);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_messages() {
        let offer = FileTransferMessage::Offer(FileOffer {
            file_hash: "abcd123".into(),
            file_name: "foto.jpg".into(),
            file_size: 1048576,
            total_chunks: 16,
            sender_pubkey: "alice_key".into(),
            sender_name: "Alice".into(),
            recipient_pubkey: "bob_key".into(),
        });

        let bytes = offer.to_bytes().expect("Deve serializar");
        let decoded = FileTransferMessage::from_bytes(&bytes).expect("Deve desserializar");
        assert_eq!(offer, decoded);
    }
}
