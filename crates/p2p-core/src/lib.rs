pub mod b64;
pub mod files;
pub mod identity;
pub mod community;
pub mod api;
pub mod protocol;
pub mod node;
pub mod bootstrap;
pub mod tracker;
pub mod relay;
pub mod voice;
pub mod file_transfer;
pub mod screen;

pub use identity::UserIdentity;
pub use api::{peer_id_from_pubkey_hex, ChatMessage, CoreCommand, CoreEvent};
pub use community::{Channel, ChannelType, ServerMessage, ServerRegistry, Space};
pub use node::{
    dht_discovery_key, make_agent_version, parse_agent_version, P2PNode, AGENT_VERSION_PREFIX,
    DHT_DISCOVERY_NAMESPACE,
};
pub use bootstrap::{IPFS_BOOTSTRAP_NODES, OPENTRACKER_SERVERS, get_ipfs_bootstrap_multiaddrs};
pub use tracker::{TorrentTrackerClient, make_info_hash};
pub use relay::{RelayManager, MAX_RELAY_RESERVATIONS};
pub use voice::{
    AudioCodec, AudioDeviceManager, AudioEngineError, JitterBuffer, VoiceEngine, VoicePacket,
    calculate_vad_energy, CHANNELS, FRAME_SIZE, SAMPLE_RATE,
};
pub use screen::{ScreenAnnounce, ScreenCaptureEngine, ScreenInfo, ScreenPacket, VideoCodec};
