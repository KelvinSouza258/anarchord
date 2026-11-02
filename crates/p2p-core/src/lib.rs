pub mod identity;
pub mod server;
pub mod api;
pub mod protocol;
pub mod node;
pub mod bootstrap;
pub mod tracker;
pub mod voice;
pub mod file_transfer;
pub mod screen;

pub use identity::UserIdentity;
pub use server::{ServerMetadata, ServerPayload, Channel, ChannelType};
pub use api::{CoreCommand, CoreEvent, ChatMessage};
pub use node::P2PNode;
pub use bootstrap::{IPFS_BOOTSTRAP_NODES, OPENTRACKER_SERVERS, get_ipfs_bootstrap_multiaddrs};
pub use tracker::{TorrentTrackerClient, make_info_hash};
pub use file_transfer::{
    calculate_file_hash, chunk_file, FileChunk, FileDecision, FileOffer, FileReceiver,
    FileTransferMessage, CHUNK_SIZE,
};
pub use voice::{
    AudioCodec, AudioDeviceManager, AudioEngineError, JitterBuffer, VoiceEngine, VoicePacket,
    calculate_vad_energy, CHANNELS, FRAME_SIZE, SAMPLE_RATE,
};
pub use screen::{ScreenCaptureEngine, ScreenInfo, ScreenPacket, VideoCodec};
