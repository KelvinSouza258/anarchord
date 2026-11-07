//! Firewall unificado do nó (`NodeFirewall` - Issue #48).
//!
//! Protege o nó e a malha P2P contra DDoS, flood de mensagens, pacotes inválidos/falsificados,
//! rotação gratuita de identidades (Sybil no mesmo IP), bombas de pacotes grandes por tópico
//! e abuso de Circuit Relay v2.
//!
//! ## Princípios de Segurança
//! 1. **Autenticação de Transporte (`ValidationMode::Strict`):** O `message.source` (`PeerId`)
//!    já é assinado e verificado pelo `libp2p` na camada de transporte antes de chegar ao runtime.
//!    A chave pública extraída do `PeerId` nunca pode ser falsificada.
//! 2. **Anti-Incriminação (*Anti-Spoofing*):** Pacotes com assinatura interna inválida ou corrompidos
//!    punem exclusivamente o `PeerId` / IP autenticado na conexão de transporte, nunca o campo
//!    textual `author_pubkey` alegado dentro do payload.
//! 3. **Políticas Assimétricas (Amigo vs. Desconhecido):** Pares presentes na lista local de amigos
//!    têm limites amplos (ou isenção configurável) e imunidade ao disjuntor global e ao bloqueio por IP compartilhado.
//! 4. **Defesa Anti-Sybil por IP:** Para desconhecidos, o bloqueio progressivo (`1m → 5m → 30m → 24h`)
//!    também vincula o IP de origem, impedindo que o atacante burle o bloqueio gerando novas chaves Ed25519.
//! 5. **Controle de Circuit Relay (`RelayAccessControl`):** Permite restringir o servidor de Relay local
//!    apenas para amigos (`firewall.relay_friends_only = true`) e barra reservas/circuitos de pares bloqueados.

use crate::api::pubkey_hex_from_peer_id;
use crate::community;
use crate::config::{DmPolicyConfig, FirewallConfig};
use crate::wire::{self, Kind};
use libp2p::{ multiaddr::Protocol, Multiaddr, PeerId };
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

/// Limite máximo para mensagens curtas (Chat, Anúncios de Tela, Lista de Pares): 16 KB
pub const MAX_SMALL_PACKET_BYTES: usize = 16 * 1024;
/// Limite máximo para pacotes de voz: 16 KB
pub const MAX_VOICE_PACKET_BYTES: usize = 16 * 1024;
/// Limite máximo para envelopes wire de DM: 64 KB
pub const MAX_DM_WIRE_BYTES: usize = 64 * 1024;
/// Limite máximo para pacotes de Controle de Servidor (Cadeia/MLS), Ofertas de Arquivo e Mailbox: 256 KB
pub const MAX_CONTROL_PACKET_BYTES: usize = 256 * 1024;
/// Limite máximo para quadros de vídeo (ScreenFrame): 1 MB
pub const MAX_VIDEO_FRAME_BYTES: usize = 1024 * 1024;

/// Categorias de tráfego monitoradas pelo `NodeFirewall`
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FirewallCategory {
    /// Mensagens de texto no Lobby ou em canais de Servidor (janela de 10s)
    Chat,
    /// Mensagens de controle: ChainRequest, KeyPackage, Subscribe, FileOffer, Peers, ScreenAnnounce (janela de 10s)
    Control,
    /// Pedidos diretos de pedaços de arquivos no enxame (`ChunkRequest`, janela de 10s)
    ChunkRequest,
    /// Pacotes inválidos: assinatura falsa, formato corrompido ou tamanho excessivo para o tópico (janela de 60s)
    InvalidPacket,
}

/// Entrada resumida de um par bloqueado pelo Firewall
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FirewallBlockEntry {
    pub pubkey: String,
    pub reason: String,
    pub blocked_until: u64,
    pub offense_level: u32,
}

/// Resultado da inspeção de tráfego pelo `NodeFirewall`
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FirewallVerdict {
    /// Tráfego permitido
    Allowed,
    /// Remetente já estava bloqueado, disjuntor global ativo ou política recusou silenciosamente
    DroppedSilently { reason: String },
    /// Remetente acabou de violar um limite e entrou em bloqueio progressivo!
    /// `send_courtesy`: true se devemos enviar 1 única mensagem de cortesia avisando do bloqueio (usado em DMs).
    NewlyBlocked {
        reason: String,
        duration_secs: u64,
        blocked_until: u64,
        offense_level: u32,
        send_courtesy: bool,
    },
}

/// Alias de compatibilidade com o código existente de DMs
pub type DmFirewallVerdict = FirewallVerdict;

/// Estado de contadores em janela deslizante e histórico de infrações de um par
#[derive(Clone, Debug, Default)]
pub(crate) struct PeerFirewallState {
    /// Timestamps UNIX de DMs online recebidas nos últimos 60s
    pub(crate) dm_online_timestamps: Vec<u64>,
    /// Timestamps UNIX de DMs offline (Mailbox) abertas na última 1h (3600s)
    pub(crate) dm_offline_timestamps: Vec<u64>,
    /// Timestamps UNIX de mensagens de chat (Lobby/Servidor) nos últimos 10s
    pub(crate) chat_timestamps: Vec<u64>,
    /// Timestamps UNIX de pacotes de controle nos últimos 10s
    pub(crate) control_timestamps: Vec<u64>,
    /// Timestamps UNIX de pedidos de pedaços de arquivo (`ChunkRequest`) nos últimos 10s
    pub(crate) chunk_timestamps: Vec<u64>,
    /// Timestamps UNIX de pacotes inválidos/corrompidos nos últimos 60s
    pub(crate) invalid_timestamps: Vec<u64>,
    /// Nível de reincidência de infrações (1 = 60s, 2 = 300s, 3 = 1800s, 4+ = 86400s)
    pub(crate) offense_level: u32,
    /// Timestamp UNIX da última infração (para decaimento por bom comportamento)
    pub(crate) last_offense_at: u64,
    /// Se estiver bloqueado, até qual timestamp UNIX o bloqueio vale
    pub(crate) blocked_until: Option<u64>,
    /// Motivo do bloqueio atual
    pub(crate) block_reason: String,
    /// Se já enviamos aviso de cortesia para o bloqueio atual (evita ping-pong / amplificação)
    pub(crate) courtesy_sent_for_current_block: bool,
    /// Último IP conhecido deste par
    pub(crate) last_ip: Option<IpAddr>,
}

#[derive(Clone, Debug)]
struct IpBlockState {
    blocked_until: u64,
    reason: String,
    offense_level: u32,
}

/// Estado compartilhado com os `RateLimiter`s do `libp2p::relay::Behaviour`
#[derive(Default, Debug)]
struct RelayAccessInner {
    friends_only: bool,
    friends: HashSet<String>,
    blocked_pubkeys: HashSet<String>,
    blocked_ips: HashSet<IpAddr>,
}

/// Controlador thread-safe compartilhado entre o `Runtime` (`NodeFirewall`) e o servidor `libp2p-relay`.
/// Permite que o Circuit Relay v2 aceite apenas amigos (`relay_friends_only = true`) e barre pares/IPs bloqueados.
#[derive(Clone, Default, Debug)]
pub struct RelayAccessControl {
    inner: Arc<RwLock<RelayAccessInner>>,
}

impl RelayAccessControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_friends_only(&self, friends_only: bool) {
        if let Ok(mut guard) = self.inner.write() {
            guard.friends_only = friends_only;
        }
    }

    pub fn is_friends_only(&self) -> bool {
        self.inner.read().map(|g| g.friends_only).unwrap_or(false)
    }

    pub fn update_friends(&self, friends: impl IntoIterator<Item = String>) {
        if let Ok(mut guard) = self.inner.write() {
            guard.friends = friends.into_iter().map(|s| s.trim().to_lowercase()).collect();
        }
    }

    pub fn set_blocked_pubkey(&self, pubkey: &str, blocked: bool) {
        if let Ok(mut guard) = self.inner.write() {
            let pk = pubkey.trim().to_lowercase();
            if blocked {
                guard.blocked_pubkeys.insert(pk);
            } else {
                guard.blocked_pubkeys.remove(&pk);
            }
        }
    }

    pub fn set_blocked_ip(&self, ip: IpAddr, blocked: bool) {
        if let Ok(mut guard) = self.inner.write() {
            if blocked {
                guard.blocked_ips.insert(ip);
            } else {
                guard.blocked_ips.remove(&ip);
            }
        }
    }

    /// Avalia se o par `(peer, addr)` pode reservar vaga ou abrir circuito no nosso Relay Server.
    pub fn check_relay_access(&self, peer: &PeerId, addr: &Multiaddr) -> bool {
        let Ok(guard) = self.inner.read() else {
            return false;
        };
        let pubkey = pubkey_hex_from_peer_id(peer).map(|pk| pk.to_lowercase());
        if let Some(ref pk) = pubkey {
            if guard.blocked_pubkeys.contains(pk) {
                return false;
            }
            if guard.friends.contains(pk) {
                return true;
            }
            if guard.friends_only {
                return false;
            }
        } else if guard.friends_only {
            return false;
        }

        if let Some(ip) = extract_ip_from_multiaddr(addr) {
            if !ip.is_loopback() && guard.blocked_ips.contains(&ip) {
                return false;
            }
        }
        true
    }
}

/// Extrai o primeiro endereço IP (`Ip4` ou `Ip6`) presente num `Multiaddr`.
pub fn extract_ip_from_multiaddr(addr: &Multiaddr) -> Option<IpAddr> {
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ip) => return Some(IpAddr::V4(ip)),
            Protocol::Ip6(ip) => return Some(IpAddr::V6(ip)),
            _ => {}
        }
    }
    None
}

/// Firewall central unificado do nó (`p2p-core`).
pub struct NodeFirewall {
    pub(crate) peers: HashMap<String, PeerFirewallState>,
    /// Bloqueios ativos por IP (defesa Anti-Sybil contra rotação gratuita de chaves no mesmo IP)
    blocked_ips: HashMap<IpAddr, IpBlockState>,
    /// Conexões ativas por IP externo (para limitar flood de conexões por IP)
    active_conns_per_ip: HashMap<IpAddr, HashSet<PeerId>>,
    /// Timestamps de pacotes de desconhecidos nos últimos 10s (Disjuntor Global Under Attack)
    stranger_global_timestamps: Vec<u64>,
    /// Se `true`, também aplica bloqueio de IP em endereços de loopback (usado em testes unitários de Sybil)
    track_loopback_ips: bool,
    /// Ponte sincronizada com o `RateLimiter` do `libp2p-relay`
    relay_access: RelayAccessControl,
}

/// Alias de compatibilidade
pub type DmFirewall = NodeFirewall;

impl Default for NodeFirewall {
    fn default() -> Self {
        Self::new()
    }
}

impl NodeFirewall {
    pub fn new() -> Self {
        Self {
            peers: HashMap::new(),
            blocked_ips: HashMap::new(),
            active_conns_per_ip: HashMap::new(),
            stranger_global_timestamps: Vec::new(),
            track_loopback_ips: false,
            relay_access: RelayAccessControl::new(),
        }
    }

    pub fn with_relay_access(relay_access: RelayAccessControl) -> Self {
        Self {
            relay_access,
            ..Self::new()
        }
    }

    pub fn relay_access(&self) -> RelayAccessControl {
        self.relay_access.clone()
    }

    /// Habilita rastreamento de bloqueio por IP mesmo em loopback (`127.0.0.1`), útil para testes unitários de Sybil.
    pub fn set_track_loopback_ips(&mut self, enabled: bool) {
        self.track_loopback_ips = enabled;
    }

    fn should_track_ip(&self, ip: &IpAddr) -> bool {
        self.track_loopback_ips || !ip.is_loopback()
    }

    /// Calcula a duração do bloqueio progressivo segundo o nível de reincidência:
    /// Nível 1 = 1 min (60s), Nível 2 = 5 min (300s), Nível 3 = 30 min (1800s), Nível 4+ = 24h (86400s)
    pub fn block_duration_for_level(level: u32) -> u64 {
        match level {
            0 | 1 => 60,
            2 => 300,
            3 => 1_800,
            _ => 86_400,
        }
    }

    /// Determina o tamanho máximo permitido em bytes para um pacote Gossipsub no tópico e cabeçalho wire informados.
    /// Barreira O(1) executada antes de qualquer deserialização ou criptografia.
    pub fn max_packet_bytes_for_topic(topic: &str, raw_data: &[u8]) -> usize {
        // Tópicos de conteúdo cifrado de servidor (MLS) ou de enxame de arquivos podem carregar ofertas/quadros
        if community::parse_server_content_topic(topic).is_some() {
            return MAX_VIDEO_FRAME_BYTES;
        }
        if community::parse_server_control_topic(topic).is_some() || topic == crate::dm::MAILBOX_TOPIC {
            return MAX_CONTROL_PACKET_BYTES;
        }
        if topic.starts_with(crate::dm::DM_TOPIC_PREFIX) || topic.starts_with("anarchord-dm-") {
            return MAX_DM_WIRE_BYTES;
        }
        if topic.starts_with("anarchord/file/") {
            return MAX_CONTROL_PACKET_BYTES;
        }

        // Inspeção O(1) do discriminador Kind no cabeçalho wire `[version, kind, ...]`
        if raw_data.len() >= 2 && wire::is_supported_version(raw_data[0]) {
            match Kind::from_byte(raw_data[1]) {
                Some(Kind::Chat) | Some(Kind::ScreenAnnounce) | Some(Kind::Peers) => {
                    return MAX_SMALL_PACKET_BYTES;
                }
                Some(Kind::Voice) => return MAX_VOICE_PACKET_BYTES,
                Some(Kind::DirectMessage) => return MAX_DM_WIRE_BYTES,
                Some(Kind::Swarm) | Some(Kind::Server) | Some(Kind::Mailbox) => {
                    return MAX_CONTROL_PACKET_BYTES;
                }
                Some(Kind::ScreenFrame) => return MAX_VIDEO_FRAME_BYTES,
                None => return MAX_SMALL_PACKET_BYTES,
            }
        }

        MAX_SMALL_PACKET_BYTES
    }

    /// Registra a abertura de uma conexão e verifica se o par ou IP (para desconhecidos) está bloqueado
    /// ou excedeu o limite de conexões por IP.
    pub fn check_incoming_connection(
        &mut self,
        peer_id: &PeerId,
        pubkey: Option<&str>,
        addr: &Multiaddr,
        is_my_friend: bool,
        cfg: &FirewallConfig,
        now: u64,
    ) -> FirewallVerdict {
        let resolved_pk = pubkey
            .map(|s| s.trim().to_lowercase())
            .or_else(|| pubkey_hex_from_peer_id(peer_id).map(|s| s.to_lowercase()))
            .unwrap_or_else(|| peer_id.to_string().to_lowercase());

        let ip_opt = extract_ip_from_multiaddr(addr);
        if let Some(ip) = ip_opt {
            self.peers.entry(resolved_pk.clone()).or_default().last_ip = Some(ip);
        }

        // 1. Verifica bloqueio direto na chave/identidade
        if self.is_blocked(&resolved_pk, now) {
            let reason = self
                .peers
                .get(&resolved_pk)
                .map(|s| s.block_reason.clone())
                .unwrap_or_else(|| "par bloqueado".to_string());
            return FirewallVerdict::DroppedSilently { reason };
        }

        // 2. Para desconhecidos, verifica bloqueio Anti-Sybil por IP e limite de conexões por IP
        if !is_my_friend {
            if let Some(ip) = ip_opt {
                if self.should_track_ip(&ip) {
                    if let Some(ip_block) = self.blocked_ips.get(&ip).cloned() {
                        if now < ip_block.blocked_until {
                            // Propaga o bloqueio do IP para a nova identidade Sybil!
                            let state = self.peers.entry(resolved_pk.clone()).or_default();
                            state.offense_level = ip_block.offense_level;
                            state.blocked_until = Some(ip_block.blocked_until);
                            state.block_reason = format!("IP {} bloqueado ({})", ip, ip_block.reason);
                            self.relay_access.set_blocked_pubkey(&resolved_pk, true);
                            return FirewallVerdict::DroppedSilently {
                                reason: state.block_reason.clone(),
                            };
                        } else {
                            self.blocked_ips.remove(&ip);
                            self.relay_access.set_blocked_ip(ip, false);
                        }
                    }

                    let conns = self.active_conns_per_ip.entry(ip).or_default();
                    if !conns.contains(peer_id) && conns.len() >= cfg.max_connections_per_ip {
                        return FirewallVerdict::DroppedSilently {
                            reason: format!(
                                "limite de conexões simultâneas por IP excedido ({} em {})",
                                cfg.max_connections_per_ip, ip
                            ),
                        };
                    }
                    conns.insert(*peer_id);
                }
            }
        }

        FirewallVerdict::Allowed
    }

    /// Registra o fechamento completo das conexões de um `PeerId`
    pub fn on_connection_closed(&mut self, peer_id: &PeerId) {
        self.active_conns_per_ip.retain(|_, set| {
            set.remove(peer_id);
            !set.is_empty()
        });
    }

    /// Associa um endereço IP a uma `pubkey` (útil quando o endereço é conhecido na conexão)
    pub fn register_peer_ip(&mut self, pubkey: &str, ip: IpAddr) {
        let pk = pubkey.trim().to_lowercase();
        self.peers.entry(pk).or_default().last_ip = Some(ip);
    }

    /// Verifica se uma mensagem genérica do nó (`Chat`, `Control`, `ChunkRequest`, `InvalidPacket`)
    /// deve ser permitida ou bloqueada pelo `NodeFirewall`.
    pub fn check_packet(
        &mut self,
        sender_pubkey: &str,
        is_my_friend: bool,
        category: FirewallCategory,
        cfg: &FirewallConfig,
        now: u64,
    ) -> FirewallVerdict {
        let pk = sender_pubkey.trim().to_lowercase();

        // 1. Verifica bloqueio por IP (Anti-Sybil para desconhecidos)
        let last_ip = self.peers.get(&pk).and_then(|s| s.last_ip);
        if !is_my_friend {
            if let Some(ip) = last_ip {
                if self.should_track_ip(&ip) {
                    if let Some(ip_block) = self.blocked_ips.get(&ip).cloned() {
                        if now < ip_block.blocked_until {
                            let state = self.peers.entry(pk.clone()).or_default();
                            if state.blocked_until.is_none() {
                                state.offense_level = ip_block.offense_level;
                                state.blocked_until = Some(ip_block.blocked_until);
                                state.block_reason = format!("IP {} bloqueado ({})", ip, ip_block.reason);
                                self.relay_access.set_blocked_pubkey(&pk, true);
                            }
                            return FirewallVerdict::DroppedSilently {
                                reason: state.block_reason.clone(),
                            };
                        } else {
                            self.blocked_ips.remove(&ip);
                            self.relay_access.set_blocked_ip(ip, false);
                        }
                    }
                }
            }
        }

        let state = self.peers.entry(pk.clone()).or_default();

        // 2. Verifica se já está bloqueado ativamente
        if let Some(until) = state.blocked_until {
            if now < until {
                return FirewallVerdict::DroppedSilently {
                    reason: state.block_reason.clone(),
                };
            } else {
                Self::clear_block_state(state);
                self.relay_access.set_blocked_pubkey(&pk, false);
            }
        }

        // 3. Decaimento por bom comportamento: reduz 1 nível a cada 1h limpa
        if state.offense_level > 0 && now.saturating_sub(state.last_offense_at) >= 3_600 {
            let hours_clean = (now.saturating_sub(state.last_offense_at) / 3_600) as u32;
            state.offense_level = state.offense_level.saturating_sub(hours_clean);
        }

        // 4. Disjuntor Global (Under Attack) para desconhecidos (exceto ao registrar InvalidPacket, que deve punir o par)
        if !is_my_friend && category != FirewallCategory::InvalidPacket {
            self.stranger_global_timestamps.retain(|&t| now.saturating_sub(t) < 10);
            if self.stranger_global_timestamps.len() as u32 >= cfg.stranger_global_msgs_per_10s {
                return FirewallVerdict::DroppedSilently {
                    reason: format!(
                        "disjuntor global anti-DDoS ativo ({} pacotes/10s de desconhecidos)",
                        cfg.stranger_global_msgs_per_10s
                    ),
                };
            }
            self.stranger_global_timestamps.push(now);
        }

        // 5. Amigos isentos (`exempt_friends = true`) passam direto em Chat, Control e ChunkRequest
        if is_my_friend && cfg.exempt_friends && category != FirewallCategory::InvalidPacket {
            return FirewallVerdict::Allowed;
        }

        let role = if is_my_friend { "amigo" } else { "desconhecido" };

        let verdict = match category {
            FirewallCategory::Chat => {
                let state = self.peers.get_mut(&pk).unwrap();
                state.chat_timestamps.retain(|&t| now.saturating_sub(t) < 10);
                let limit = if is_my_friend {
                    cfg.friend_chat_per_10s
                } else {
                    cfg.stranger_chat_per_10s
                };
                if state.chat_timestamps.len() as u32 >= limit {
                    Self::trigger_block(
                        state,
                        format!("flood de chat de {} (> {} msg/10s)", role, limit),
                        false,
                        now,
                    )
                } else {
                    state.chat_timestamps.push(now);
                    FirewallVerdict::Allowed
                }
            }
            FirewallCategory::Control => {
                let state = self.peers.get_mut(&pk).unwrap();
                state.control_timestamps.retain(|&t| now.saturating_sub(t) < 10);
                let limit = if is_my_friend {
                    cfg.friend_control_per_10s
                } else {
                    cfg.stranger_control_per_10s
                };
                if state.control_timestamps.len() as u32 >= limit {
                    Self::trigger_block(
                        state,
                        format!("excesso de pacotes de controle de {} (> {}/10s)", role, limit),
                        false,
                        now,
                    )
                } else {
                    state.control_timestamps.push(now);
                    FirewallVerdict::Allowed
                }
            }
            FirewallCategory::ChunkRequest => {
                let state = self.peers.get_mut(&pk).unwrap();
                state.chunk_timestamps.retain(|&t| now.saturating_sub(t) < 10);
                let limit = if is_my_friend {
                    cfg.friend_chunk_reqs_per_10s
                } else {
                    cfg.stranger_chunk_reqs_per_10s
                };
                if state.chunk_timestamps.len() as u32 >= limit {
                    Self::trigger_block(
                        state,
                        format!("abuso de pedidos de pedaços de {} (> {}/10s)", role, limit),
                        false,
                        now,
                    )
                } else {
                    state.chunk_timestamps.push(now);
                    FirewallVerdict::Allowed
                }
            }
            FirewallCategory::InvalidPacket => {
                let state = self.peers.get_mut(&pk).unwrap();
                state.invalid_timestamps.retain(|&t| now.saturating_sub(t) < 60);
                state.invalid_timestamps.push(now);
                if state.invalid_timestamps.len() as u32 >= cfg.invalid_packets_per_min {
                    Self::trigger_block(
                        state,
                        format!(
                            "excesso de pacotes inválidos/corrompidos ({}/min)",
                            cfg.invalid_packets_per_min
                        ),
                        false,
                        now,
                    )
                } else {
                    FirewallVerdict::DroppedSilently {
                        reason: "pacote inválido descartado".to_string(),
                    }
                }
            }
        };

        self.sync_block_side_effects(&pk, is_my_friend, &verdict);
        verdict
    }

    /// Verifica se uma DM (online ou offline) vinda de `sender_pubkey` deve ser aceita ou bloqueada.
    /// Mantém 100% do comportamento de `DmFirewall` integrado ao `NodeFirewall` unificado.
    pub fn check_incoming_dm(
        &mut self,
        sender_pubkey: &str,
        is_my_friend: bool,
        message_len_bytes: usize,
        is_offline_envelope: bool,
        policy: &DmPolicyConfig,
        now: u64,
    ) -> FirewallVerdict {
        let pk = sender_pubkey.trim().to_lowercase();

        // Verifica bloqueio por IP para desconhecidos
        let last_ip = self.peers.get(&pk).and_then(|s| s.last_ip);
        if !is_my_friend {
            if let Some(ip) = last_ip {
                if self.should_track_ip(&ip) {
                    if let Some(ip_block) = self.blocked_ips.get(&ip).cloned() {
                        if now < ip_block.blocked_until {
                            let state = self.peers.entry(pk.clone()).or_default();
                            if state.blocked_until.is_none() {
                                state.offense_level = ip_block.offense_level;
                                state.blocked_until = Some(ip_block.blocked_until);
                                state.block_reason = format!("IP {} bloqueado ({})", ip, ip_block.reason);
                                self.relay_access.set_blocked_pubkey(&pk, true);
                            }
                            return FirewallVerdict::DroppedSilently {
                                reason: state.block_reason.clone(),
                            };
                        } else {
                            self.blocked_ips.remove(&ip);
                            self.relay_access.set_blocked_ip(ip, false);
                        }
                    }
                }
            }
        }

        let state = self.peers.entry(pk.clone()).or_default();

        // 1. Verifica se já está bloqueado ativamente
        if let Some(until) = state.blocked_until {
            if now < until {
                return FirewallVerdict::DroppedSilently {
                    reason: state.block_reason.clone(),
                };
            } else {
                Self::clear_block_state(state);
                self.relay_access.set_blocked_pubkey(&pk, false);
            }
        }

        // Decaimento por bom comportamento: se passou mais de 1h sem infração, reduz o nível de reincidência
        if state.offense_level > 0 && now.saturating_sub(state.last_offense_at) >= 3_600 {
            let hours_clean = (now.saturating_sub(state.last_offense_at) / 3_600) as u32;
            state.offense_level = state.offense_level.saturating_sub(hours_clean);
        }

        // 2. Se não é amigo nosso e `allow_strangers == false`, recusa
        if !is_my_friend && !policy.allow_strangers {
            let verdict = Self::trigger_block(
                state,
                "DMs de desconhecidos desativadas (apenas amigos)".to_string(),
                policy.send_courtesy_notice,
                now,
            );
            self.sync_block_side_effects(&pk, is_my_friend, &verdict);
            return verdict;
        }

        // 3. Limite de tamanho da mensagem (diferenciado entre Amigo e Desconhecido)
        let max_bytes = if is_my_friend {
            policy.friend_max_message_bytes
        } else {
            policy.stranger_max_message_bytes
        };
        if message_len_bytes > max_bytes {
            let role = if is_my_friend { "amigo" } else { "desconhecido" };
            let verdict = Self::trigger_block(
                state,
                format!(
                    "mensagem excedeu tamanho máximo para {} ({} > {} bytes)",
                    role, message_len_bytes, max_bytes
                ),
                policy.send_courtesy_notice,
                now,
            );
            self.sync_block_side_effects(&pk, is_my_friend, &verdict);
            return verdict;
        }

        // 4. Limite de taxa em janela deslizante
        let verdict = if is_offline_envelope && !is_my_friend {
            state.dm_offline_timestamps.retain(|&t| now.saturating_sub(t) < 3_600);
            if state.dm_offline_timestamps.len() as u32 >= policy.stranger_offline_limit_per_hour {
                Self::trigger_block(
                    state,
                    format!(
                        "limite de DMs offline de desconhecido excedido ({}/h)",
                        policy.stranger_offline_limit_per_hour
                    ),
                    policy.send_courtesy_notice,
                    now,
                )
            } else {
                state.dm_offline_timestamps.push(now);
                FirewallVerdict::Allowed
            }
        } else {
            state.dm_online_timestamps.retain(|&t| now.saturating_sub(t) < 60);
            let max_per_min = if is_my_friend {
                policy.friend_rate_limit_per_min
            } else {
                policy.stranger_rate_limit_per_min
            };
            if state.dm_online_timestamps.len() as u32 >= max_per_min {
                let role = if is_my_friend { "amigo" } else { "desconhecido" };
                Self::trigger_block(
                    state,
                    format!("limite de taxa para {} excedido ({} msg/min)", role, max_per_min),
                    policy.send_courtesy_notice,
                    now,
                )
            } else {
                state.dm_online_timestamps.push(now);
                FirewallVerdict::Allowed
            }
        };

        self.sync_block_side_effects(&pk, is_my_friend, &verdict);
        verdict
    }

    /// Registra uma infração imediata de pacote inválido/assinatura corrompida (atalho direto)
    pub fn record_invalid_packet(&mut self, sender_pubkey: &str, now: u64) -> Option<(u64, u64, u32)> {
        let pk = sender_pubkey.trim().to_lowercase();
        let state = self.peers.entry(pk.clone()).or_default();
        if let FirewallVerdict::NewlyBlocked {
            duration_secs,
            blocked_until,
            offense_level,
            ..
        } = Self::trigger_block(state, "assinatura ou pacote inválido".to_string(), false, now)
        {
            self.relay_access.set_blocked_pubkey(&pk, true);
            Some((duration_secs, blocked_until, offense_level))
        } else {
            None
        }
    }

    fn sync_block_side_effects(&mut self, pk: &str, is_my_friend: bool, verdict: &FirewallVerdict) {
        if let FirewallVerdict::NewlyBlocked {
            reason,
            blocked_until,
            offense_level,
            ..
        } = verdict
        {
            self.relay_access.set_blocked_pubkey(pk, true);
            if !is_my_friend {
                if let Some(ip) = self.peers.get(pk).and_then(|s| s.last_ip) {
                    if self.should_track_ip(&ip) {
                        self.blocked_ips.insert(
                            ip,
                            IpBlockState {
                                blocked_until: *blocked_until,
                                reason: reason.clone(),
                                offense_level: *offense_level,
                            },
                        );
                        self.relay_access.set_blocked_ip(ip, true);
                    }
                }
            }
        }
    }

    fn clear_block_state(state: &mut PeerFirewallState) {
        state.blocked_until = None;
        state.courtesy_sent_for_current_block = false;
        state.dm_online_timestamps.clear();
        state.dm_offline_timestamps.clear();
        state.chat_timestamps.clear();
        state.control_timestamps.clear();
        state.chunk_timestamps.clear();
        state.invalid_timestamps.clear();
    }

    fn trigger_block(
        state: &mut PeerFirewallState,
        reason: String,
        allow_courtesy: bool,
        now: u64,
    ) -> FirewallVerdict {
        state.offense_level = state.offense_level.saturating_add(1);
        state.last_offense_at = now;
        let duration_secs = Self::block_duration_for_level(state.offense_level);
        let blocked_until = now.saturating_add(duration_secs);
        state.blocked_until = Some(blocked_until);
        state.block_reason = reason.clone();
        let send_courtesy = allow_courtesy && !state.courtesy_sent_for_current_block;
        if send_courtesy {
            state.courtesy_sent_for_current_block = true;
        }
        FirewallVerdict::NewlyBlocked {
            reason,
            duration_secs,
            blocked_until,
            offense_level: state.offense_level,
            send_courtesy,
        }
    }

    /// Desbloqueia manualmente um par (ou automaticamente quando adicionado como amigo)
    pub fn unblock(&mut self, pubkey: &str) -> bool {
        let pk = pubkey.trim().to_lowercase();
        self.relay_access.set_blocked_pubkey(&pk, false);
        if let Some(state) = self.peers.get_mut(&pk) {
            let was_blocked = state.blocked_until.is_some();
            if let Some(ip) = state.last_ip {
                self.blocked_ips.remove(&ip);
                self.relay_access.set_blocked_ip(ip, false);
            }
            state.offense_level = 0;
            Self::clear_block_state(state);
            was_blocked
        } else {
            false
        }
    }

    /// Limpa bloqueios expirados e retorna a lista de pubkeys que foram desbloqueadas
    pub fn purge_expired_blocks(&mut self, now: u64) -> Vec<String> {
        let mut unblocked = Vec::new();
        for (pk, state) in self.peers.iter_mut() {
            if let Some(until) = state.blocked_until {
                if now >= until {
                    Self::clear_block_state(state);
                    self.relay_access.set_blocked_pubkey(pk, false);
                    unblocked.push(pk.clone());
                }
            }
        }
        let relay_access = self.relay_access.clone();
        self.blocked_ips.retain(|ip, b| {
            let active = now < b.blocked_until;
            if !active {
                relay_access.set_blocked_ip(*ip, false);
            }
            active
        });
        unblocked
    }

    /// Retorna se o par está bloqueado ativamente neste instante
    pub fn is_blocked(&self, pubkey: &str, now: u64) -> bool {
        let pk = pubkey.trim().to_lowercase();
        if let Some(state) = self.peers.get(&pk) {
            if let Some(until) = state.blocked_until {
                if now < until {
                    return true;
                }
            }
            if let Some(ip) = state.last_ip {
                if self.should_track_ip(&ip) {
                    if let Some(ip_b) = self.blocked_ips.get(&ip) {
                        if now < ip_b.blocked_until {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    /// Lista todos os pares atualmente bloqueados
    pub fn active_blocks(&self, now: u64) -> Vec<FirewallBlockEntry> {
        let mut out: Vec<FirewallBlockEntry> = self
            .peers
            .iter()
            .filter_map(|(pk, s)| {
                let until = s.blocked_until?;
                (until > now).then(|| FirewallBlockEntry {
                    pubkey: pk.clone(),
                    reason: s.block_reason.clone(),
                    blocked_until: until,
                    offense_level: s.offense_level,
                })
            })
            .collect();
        out.sort_by(|a, b| a.pubkey.cmp(&b.pubkey));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UserIdentity;

    #[test]
    fn test_chat_flood_and_progressive_backoff_with_decay() {
        let mut fw = NodeFirewall::new();
        let cfg = FirewallConfig {
            stranger_chat_per_10s: 5,
            friend_chat_per_10s: 20,
            ..Default::default()
        };
        let attacker = "aa".repeat(32);

        // 5 mensagens em 10s passam
        for i in 0..5 {
            assert_eq!(
                fw.check_packet(&attacker, false, FirewallCategory::Chat, &cfg, 1000 + i),
                FirewallVerdict::Allowed
            );
        }

        // 6ª mensagem estoura o limite -> Bloqueio Nível 1 (60s)
        let v = fw.check_packet(&attacker, false, FirewallCategory::Chat, &cfg, 1005);
        assert!(matches!(
            v,
            FirewallVerdict::NewlyBlocked {
                duration_secs: 60,
                blocked_until: 1065,
                offense_level: 1,
                ..
            }
        ));

        // Durante o bloqueio, é descartado silenciosamente
        assert!(matches!(
            fw.check_packet(&attacker, false, FirewallCategory::Chat, &cfg, 1030),
            FirewallVerdict::DroppedSilently { .. }
        ));

        // Após expirar (t = 1066), volta a falar normalmente; mas se reincidir logo, sobe para Nível 2 (300s)!
        for i in 0..5 {
            assert_eq!(
                fw.check_packet(&attacker, false, FirewallCategory::Chat, &cfg, 1066 + i),
                FirewallVerdict::Allowed
            );
        }
        let v2 = fw.check_packet(&attacker, false, FirewallCategory::Chat, &cfg, 1071);
        assert!(matches!(
            v2,
            FirewallVerdict::NewlyBlocked {
                duration_secs: 300,
                offense_level: 2,
                ..
            }
        ));

        // Se passar 2 horas de bom comportamento após o desbloqueio (t = 1071 + 7200 = 8271), o nível decai!
        for i in 0..5 {
            assert_eq!(
                fw.check_packet(&attacker, false, FirewallCategory::Chat, &cfg, 8272 + i),
                FirewallVerdict::Allowed
            );
        }
        let v_after_decay = fw.check_packet(&attacker, false, FirewallCategory::Chat, &cfg, 8277);
        assert!(matches!(
            v_after_decay,
            FirewallVerdict::NewlyBlocked {
                duration_secs: 60,
                offense_level: 1,
                ..
            }
        ));
    }

    #[test]
    fn test_invalid_packets_block_faster_and_never_incriminate_victim() {
        let mut fw = NodeFirewall::new();
        let cfg = FirewallConfig {
            invalid_packets_per_min: 3,
            ..Default::default()
        };
        let mallory_transport_pk = "bb".repeat(32);
        let alice_victim_pk = "cc".repeat(32);

        // Mallory envia 3 pacotes com assinatura falsa tentando fingir ser Alice.
        // O runtime passa `mallory_transport_pk` (extraído do `message.source` autenticado pelo libp2p):
        assert!(matches!(
            fw.check_packet(&mallory_transport_pk, false, FirewallCategory::InvalidPacket, &cfg, 100),
            FirewallVerdict::DroppedSilently { .. }
        ));
        assert!(matches!(
            fw.check_packet(&mallory_transport_pk, false, FirewallCategory::InvalidPacket, &cfg, 101),
            FirewallVerdict::DroppedSilently { .. }
        ));
        let v3 = fw.check_packet(&mallory_transport_pk, false, FirewallCategory::InvalidPacket, &cfg, 102);
        assert!(matches!(
            v3,
            FirewallVerdict::NewlyBlocked {
                duration_secs: 60,
                offense_level: 1,
                ..
            }
        ));

        // Mallory está bloqueado, enquanto Alice continua 100% livre!
        assert!(fw.is_blocked(&mallory_transport_pk, 110));
        assert!(!fw.is_blocked(&alice_victim_pk, 110));
        assert_eq!(
            fw.check_packet(&alice_victim_pk, true, FirewallCategory::Chat, &cfg, 110),
            FirewallVerdict::Allowed
        );
    }

    #[test]
    fn test_anti_sybil_ip_blocking_catches_identity_rotation() {
        let mut fw = NodeFirewall::new();
        let cfg = FirewallConfig {
            stranger_chat_per_10s: 2,
            ..Default::default()
        };
        let attacker_ip: IpAddr = "203.0.113.50".parse().unwrap();
        let sybil_1 = "11".repeat(32);
        let sybil_2 = "22".repeat(32);
        let honest_friend_same_nat = "ff".repeat(32);

        fw.register_peer_ip(&sybil_1, attacker_ip);
        fw.register_peer_ip(&sybil_2, attacker_ip);
        fw.register_peer_ip(&honest_friend_same_nat, attacker_ip);

        // Sybil 1 faz flood e é bloqueado no IP 203.0.113.50
        assert_eq!(fw.check_packet(&sybil_1, false, FirewallCategory::Chat, &cfg, 500), FirewallVerdict::Allowed);
        assert_eq!(fw.check_packet(&sybil_1, false, FirewallCategory::Chat, &cfg, 501), FirewallVerdict::Allowed);
        assert!(matches!(
            fw.check_packet(&sybil_1, false, FirewallCategory::Chat, &cfg, 502),
            FirewallVerdict::NewlyBlocked { .. }
        ));

        // O atacante gera uma nova chave Ed25519 (Sybil 2) no mesmo segundo e mesmo IP:
        // É barrado imediatamente na primeira mensagem!
        let v_sybil2 = fw.check_packet(&sybil_2, false, FirewallCategory::Chat, &cfg, 503);
        assert!(matches!(v_sybil2, FirewallVerdict::DroppedSilently { .. }));
        assert!(fw.is_blocked(&sybil_2, 503));

        // Já um Amigo que esteja atrás do mesmo IP/NAT corporativo NÃO é afetado pelo bloqueio de IP!
        assert_eq!(
            fw.check_packet(&honest_friend_same_nat, true, FirewallCategory::Chat, &cfg, 503),
            FirewallVerdict::Allowed
        );
    }

    #[test]
    fn test_global_circuit_breaker_under_attack_protects_friends() {
        let mut fw = NodeFirewall::new();
        let cfg = FirewallConfig {
            stranger_chat_per_10s: 10,
            stranger_global_msgs_per_10s: 6, // Disjuntor global dispara com 6 pacotes de desconhecidos
            ..Default::default()
        };

        // 3 bots diferentes mandam apenas 2 mensagens cada (abaixo do limite individual de 10!), somando 6
        for bot_idx in 1..=3u8 {
            let bot_pk = format!("{:02x}", bot_idx).repeat(32);
            assert_eq!(fw.check_packet(&bot_pk, false, FirewallCategory::Chat, &cfg, 2000), FirewallVerdict::Allowed);
            assert_eq!(fw.check_packet(&bot_pk, false, FirewallCategory::Chat, &cfg, 2001), FirewallVerdict::Allowed);
        }

        // O 4º bot tenta mandar a 1ª mensagem dele, mas o Disjuntor Global barra!
        let bot4 = "04".repeat(32);
        assert!(matches!(
            fw.check_packet(&bot4, false, FirewallCategory::Chat, &cfg, 2002),
            FirewallVerdict::DroppedSilently { .. }
        ));

        // Enquanto isso, um Amigo continua conversando normalmente sem qualquer impacto!
        let friend_pk = "99".repeat(32);
        assert_eq!(
            fw.check_packet(&friend_pk, true, FirewallCategory::Chat, &cfg, 2002),
            FirewallVerdict::Allowed
        );
    }

    #[test]
    fn test_relay_access_control_friends_only_and_blocked() {
        let relay_ctrl = RelayAccessControl::new();
        let friend_id = UserIdentity::generate();
        let friend_peer_id = PeerId::from(friend_id.to_libp2p_keypair().public());
        let friend_pk = friend_id.public_key_hex();

        let stranger_id = UserIdentity::generate();
        let stranger_peer_id = PeerId::from(stranger_id.to_libp2p_keypair().public());
        let stranger_pk = stranger_id.public_key_hex();

        let addr: Multiaddr = "/ip4/198.51.100.10/tcp/4001".parse().unwrap();

        relay_ctrl.update_friends(vec![friend_pk.clone()]);

        // Modo público padrão: aceita amigo e desconhecido (se não bloqueado)
        assert!(relay_ctrl.check_relay_access(&friend_peer_id, &addr));
        assert!(relay_ctrl.check_relay_access(&stranger_peer_id, &addr));

        // Se o desconhecido for bloqueado no NodeFirewall, o Relay recusa na hora
        relay_ctrl.set_blocked_pubkey(&stranger_pk, true);
        assert!(!relay_ctrl.check_relay_access(&stranger_peer_id, &addr));
        relay_ctrl.set_blocked_pubkey(&stranger_pk, false);

        // Modo `relay_friends_only = true`: só aceita amigos!
        relay_ctrl.set_friends_only(true);
        assert!(relay_ctrl.check_relay_access(&friend_peer_id, &addr));
        assert!(!relay_ctrl.check_relay_access(&stranger_peer_id, &addr));
    }

    #[test]
    fn test_topic_packet_size_limits() {
        let chat_bytes = [wire::VERSION, Kind::Chat as u8, 1, 2, 3];
        assert_eq!(
            NodeFirewall::max_packet_bytes_for_topic("anarchord/lobby/geral", &chat_bytes),
            MAX_SMALL_PACKET_BYTES
        );

        let video_bytes = [wire::VERSION, Kind::ScreenFrame as u8, 0];
        assert_eq!(
            NodeFirewall::max_packet_bytes_for_topic("anarchord/lobby/geral", &video_bytes),
            MAX_VIDEO_FRAME_BYTES
        );

        let dm_bytes = [wire::VERSION, Kind::DirectMessage as u8, 0];
        assert_eq!(
            NodeFirewall::max_packet_bytes_for_topic("anarchord-dm-123", &dm_bytes),
            MAX_DM_WIRE_BYTES
        );
    }
}
