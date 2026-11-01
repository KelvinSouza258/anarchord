use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ChatMessage {
    pub channel_id: String,
    pub author_pubkey: String,
    pub author_name: String,
    pub text: String,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum CoreCommand {
    CreateServer { name: String },
    JoinServer { server_id: String },
    SendTextMessage { channel_id: String, text: String },
    JoinVoiceChannel { channel_id: String },
    LeaveVoiceChannel,
    SetMute(bool),
    KickPeer { peer_id: String },
    ListPeers,
    Shutdown,
}

#[derive(Debug, Clone)]
pub enum CoreEvent {
    ServerCreated { server_id: String, name: String },
    ServerDiscovered { server_id: String, name: String },
    PeerJoined { peer_id: String },
    PeerLeft { peer_id: String },
    TextMessageReceived(ChatMessage),
    PeerSpeaking { peer_id: String, is_speaking: bool },
    VoiceDataReady { peer_id: String, samples: Vec<f32> },
    Error(String),
}
