//! Runtime de Mensagens Diretas (DM 1:1 E2EE), Sessões Efêmeras e Mailbox Offline.

use super::{CoreError, CoreEvent, Runtime};
use crate::community::{format_duration, short_id};
use crate::config::NodeConfig;
use crate::dm::{
    dm_topic, DirectMessageEnvelope, DmFirewall, DmFirewallVerdict, DmPeerSession, DmWireMessage,
    EphemeralKeyOffer, FriendRequest, FriendResponse, MailboxMessage, MailboxStore, ReceiptAck,
    StoredEnvelope, FRIEND_REQUEST_MAILBOX_TOPIC, FRIEND_RESPONSE_MAILBOX_TOPIC, MAILBOX_TOPIC,
};
use crate::identity::FriendState;
use crate::wire;
use libp2p::gossipsub::IdentTopic;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

pub(super) struct DmState {
    pub node_config: NodeConfig,
    pub config_path: Option<PathBuf>,
    pub mailbox: MailboxStore,
    /// Sessões efêmeras X25519 por chave pública (hex lowercase) do par
    pub sessions: HashMap<String, DmPeerSession>,
    /// Tópicos de DM em que já estamos inscritos
    pub subscribed_topics: HashSet<String>,
    /// Se o usuário está com uma conversa DM aberta como canal ativo: pubkey (hex lowercase) do amigo
    pub active_dm_peer: Option<String>,
    /// Firewall de aplicação local para DMs (políticas diferenciadas para Amigos vs Desconhecidos)
    pub firewall: DmFirewall,
}

impl DmState {
    pub fn new(config_path: Option<PathBuf>, mailbox_file: Option<PathBuf>, now: u64) -> Self {
        let node_config = NodeConfig::load_or_default(config_path.as_deref()).unwrap_or_default();
        let mailbox = MailboxStore::load(mailbox_file, now);
        Self {
            node_config,
            config_path,
            mailbox,
            sessions: HashMap::new(),
            subscribed_topics: HashSet::new(),
            active_dm_peer: None,
            firewall: DmFirewall::new(),
        }
    }
}

impl Runtime {
    /// Inscreve no tópico de Mailbox Offline e nos tópicos mútuos de DM de todos os amigos
    pub(super) fn init_dm_and_mailbox(&mut self) {
        let _ = self
            .node
            .swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&IdentTopic::new(MAILBOX_TOPIC));
        let friend_pks: Vec<String> = self
            .identity
            .get_friends()
            .iter()
            .map(|f| f.public_key.clone())
            .collect();
        for pk in friend_pks {
            self.subscribe_dm_with(&pk);
        }
        // Emite a lista inicial de amigos para a interface
        self.list_friends();
    }

    /// Garante que estamos inscritos no tópico determinístico de DM com `peer_pubkey`
    pub(super) fn subscribe_dm_with(&mut self, peer_pubkey: &str) -> String {
        let my_pk = self.my_pubkey();
        let topic_str = dm_topic(&my_pk, peer_pubkey);
        if self.dm.subscribed_topics.insert(topic_str.clone()) {
            let _ = self
                .node
                .swarm
                .behaviour_mut()
                .gossipsub
                .subscribe(&IdentTopic::new(&topic_str));
        }
        let clean_pk = peer_pubkey.trim().to_lowercase();
        self.dm.sessions.entry(clean_pk).or_default();
        topic_str
    }

    /// Publica nossa oferta de chave efêmera X25519 assinada para o par (Forward Secrecy)
    pub(super) fn send_ephemeral_key_offer(&mut self, peer_pubkey: &str) {
        let clean_pk = peer_pubkey.trim().to_lowercase();
        let topic_str = self.subscribe_dm_with(&clean_pk);
        let session = self.dm.sessions.entry(clean_pk.clone()).or_default();
        let offer = EphemeralKeyOffer::new_signed(
            &self.identity,
            &clean_pk,
            session.my_ephemeral_public,
            super::now_secs(),
        );
        let msg = DmWireMessage::KeyOffer(offer);
        let bytes = wire::encode(&msg);
        let _ = self.publish_gossip(IdentTopic::new(topic_str), bytes);
        self.send_key_advertisement(&clean_pk);
    }

    /// Publica nosso anúncio assinado de chave de criptografia X25519 no tópico mútuo de DM
    pub(super) fn send_key_advertisement(&mut self, peer_pubkey: &str) {
        let clean_pk = peer_pubkey.trim().to_lowercase();
        let topic_str = self.subscribe_dm_with(&clean_pk);
        let ad = self.identity.create_key_advertisement();
        let msg = DmWireMessage::KeyAdvertisement(ad);
        let bytes = wire::encode(&msg);
        let _ = self.publish_gossip(IdentTopic::new(topic_str), bytes);
    }

    /// Resolve um alvo (pubkey de 64 chars, apelido de amigo ou nick de par conectado) para `(pubkey_hex, display_name)`
    pub(super) fn resolve_dm_target(&self, target: &str) -> Option<(String, String)> {
        let trimmed = target.trim().trim_start_matches('@');
        if trimmed.is_empty() {
            return None;
        }
        // 1. Amigo pelo apelido (alias) ou pela pubkey
        if let Some(friend) = self.identity.get_friends().iter().find(|f| {
            f.alias.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(trimmed))
                || f.public_key.eq_ignore_ascii_case(trimmed)
                || (trimmed.len() >= 6 && f.public_key.starts_with(&trimmed.to_lowercase()))
        }) {
            let pk = friend.public_key.to_lowercase();
            let name = friend
                .alias
                .clone()
                .unwrap_or_else(|| self.nick_or_short(&pk));
            return Some((pk, name));
        }

        // 2. Par conectado pelo nick ou prefixo
        if let Some(peer_id) = self.find_peer(trimmed) {
            if let Some((nick, pk)) = self.peer_metadata.get(&peer_id) {
                return Some((pk.to_lowercase(), nick.clone()));
            }
        }

        // 3. Pubkey completa de 64 chars hex (mesmo sem estar nos amigos ainda)
        if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
            let pk = trimmed.to_lowercase();
            let name = self.nick_or_short(&pk);
            return Some((pk, name));
        }

        None
    }

    /// Nome amigável de um contato/par (alias de amigo > nick conectado > short_id)
    pub(super) fn friendly_name(&self, pubkey: &str) -> String {
        if let Some(friend) = self
            .identity
            .get_friends()
            .iter()
            .find(|f| f.public_key.eq_ignore_ascii_case(pubkey))
        {
            if let Some(alias) = &friend.alias {
                return alias.clone();
            }
        }
        self.nick_or_short(pubkey)
    }

    /// Verifica se uma pubkey está conectada e identificada agora no Swarm
    pub(super) fn is_pubkey_online(&self, pubkey: &str) -> bool {
        self.peer_metadata.iter().any(|(peer, (_, pk))| {
            pk.eq_ignore_ascii_case(pubkey) && self.connected_peers.contains(peer)
        })
    }

    /// Abre uma conversa privada de DM como canal ativo na TUI (`@Nome`)
    pub(super) fn open_dm(&mut self, target: &str) {
        let Some((peer_pk, peer_name)) = self.resolve_dm_target(target) else {
            return self.error(CoreError::PeerNotFound(target.to_string()));
        };
        if peer_pk.eq_ignore_ascii_case(&self.my_pubkey()) {
            return self.error(CoreError::Friend("Você não pode abrir uma DM consigo mesmo".into()));
        }
        self.subscribe_dm_with(&peer_pk);
        self.send_ephemeral_key_offer(&peer_pk);
        self.dm.active_dm_peer = Some(peer_pk.clone());

        let dm_channel_label = format!("@{}", peer_name);
        self.emit(CoreEvent::DmOpened {
            peer_pubkey: peer_pk,
            peer_name,
            channel: dm_channel_label,
        });
    }

    /// Envia uma DM (online via tópico mútuo E2EE ou offline via guardiões amigos se o destinatário não estiver conectado)
    pub(super) fn send_dm(&mut self, target: &str, text: &str, suggested_ttl: Option<u64>) {
        let Some((peer_pk, peer_name)) = self.resolve_dm_target(target) else {
            return self.error(CoreError::PeerNotFound(target.to_string()));
        };
        if peer_pk.eq_ignore_ascii_case(&self.my_pubkey()) {
            return self.error(CoreError::Friend("Você não pode enviar DM para si mesmo".into()));
        }
        let now = super::now_secs();
        let now_ms = super::now_millis();
        let topic_str = self.subscribe_dm_with(&peer_pk);
        let online = self.is_pubkey_online(&peer_pk);

        if online {
            // Garante envio de oferta de chave efêmera e cifra a DM
            self.send_ephemeral_key_offer(&peer_pk);
            let session_key = self
                .dm
                .sessions
                .get(&peer_pk)
                .and_then(|s| s.shared_session_key);
            match DirectMessageEnvelope::seal(
                &self.identity,
                &peer_pk,
                text,
                now_ms,
                session_key.as_ref(),
            ) {
                Ok(envelope) => {
                    let wire_msg = DmWireMessage::Message(envelope);
                    let bytes = wire::encode(&wire_msg);
                    let _ = self.publish_gossip(IdentTopic::new(topic_str), bytes);
                    self.emit(CoreEvent::DirectMessage {
                        peer_pubkey: peer_pk,
                        peer_name,
                        author: self.nick.clone(),
                        author_pubkey: self.my_pubkey(),
                        text: text.to_string(),
                        timestamp: now_ms,
                        offline_delivery: false,
                    });
                }
                Err(e) => self.error(CoreError::Friend(e.to_string())),
            }
        } else {
            // Destinatário offline: cria StoredEnvelope Sign-then-Seal (timestamp em ms) e delega aos amigos guardiões
            match StoredEnvelope::create_signed_and_sealed(
                &self.identity,
                &peer_pk,
                text,
                now_ms,
                suggested_ttl,
            ) {
                Ok(stored) => {
                    let env_id = stored.envelope_id.clone();
                    self.dm
                        .mailbox
                        .insert_own(stored.clone(), &self.dm.node_config, now);
                    let msg = MailboxMessage::Store(stored);
                    let bytes = wire::encode(&msg);
                    if self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes).is_ok() {
                        // Marca apenas os amigos conectados que já estão inscritos em MAILBOX_TOPIC agora
                        let mailbox_hash = IdentTopic::new(MAILBOX_TOPIC).hash();
                        let subscribed_friends: Vec<String> = self
                            .node
                            .swarm
                            .behaviour()
                            .gossipsub
                            .all_peers()
                            .filter(|(_, topics)| topics.contains(&&mailbox_hash))
                            .filter_map(|(peer, _)| self.peer_metadata.get(peer).map(|(_, pk)| pk.to_lowercase()))
                            .filter(|pk| {
                                self.identity
                                    .get_friends()
                                    .iter()
                                    .any(|f| f.public_key.eq_ignore_ascii_case(pk))
                            })
                            .collect();
                        for friend_pk in subscribed_friends {
                            self.dm.mailbox.mark_delegated_to_guardian(&env_id, &friend_pk);
                        }
                    }

                    self.emit(CoreEvent::DirectMessage {
                        peer_pubkey: peer_pk.clone(),
                        peer_name: peer_name.clone(),
                        author: self.nick.clone(),
                        author_pubkey: self.my_pubkey(),
                        text: text.to_string(),
                        timestamp: now_ms,
                        offline_delivery: true,
                    });
                    self.emit(CoreEvent::MailboxQueued {
                        recipient_pubkey: peer_pk,
                        recipient_name: peer_name,
                        envelope_id: env_id,
                        suggested_ttl,
                    });
                }
                Err(e) => self.error(CoreError::Friend(e.to_string())),
            }
        }
    }

    /// Recebe mensagem de tópico de DM (`DmWireMessage`)
    pub(super) fn on_dm_wire_message(&mut self, msg: DmWireMessage) {
        let my_pk = self.my_pubkey();
        match msg {
            DmWireMessage::KeyOffer(offer) => {
                if !offer.recipient_pubkey.eq_ignore_ascii_case(&my_pk)
                    || offer.sender_pubkey.eq_ignore_ascii_case(&my_pk)
                {
                    return;
                }
                if !offer.verify() {
                    tracing::debug!("Oferta de chave efêmera DM inválida descartada");
                    return;
                }
                let sender_pk = offer.sender_pubkey.to_lowercase();
                self.subscribe_dm_with(&sender_pk);
                let session = self.dm.sessions.entry(sender_pk.clone()).or_default();
                let had_peer_key = session.peer_ephemeral_public == Some(offer.ephemeral_pubkey);
                session.apply_peer_offer(offer.ephemeral_pubkey);
                // Responde com a nossa chave efêmera caso ainda não tenhamos respondido a esta chave
                if !had_peer_key {
                    self.send_ephemeral_key_offer(&sender_pk);
                }
            }
            DmWireMessage::KeyAdvertisement(ad) => {
                if ad.advertisement.user_id.eq_ignore_ascii_case(&my_pk) {
                    return;
                }
                if !ad.verify() {
                    tracing::debug!("Anúncio de chave de criptografia inválido descartado");
                    return;
                }
                let sender_pk = ad.advertisement.user_id.to_lowercase();
                if let Ok(updated) = self.identity.update_friend_encryption_key(&ad) {
                    if updated {
                        tracing::info!(peer = %sender_pk, epoch = ad.advertisement.epoch, "Chave de criptografia X25519 do amigo atualizada");
                        self.persist_identity();
                    }
                }
            }
            DmWireMessage::FriendRequest(req) => {
                if !req.recipient_pubkey.eq_ignore_ascii_case(&my_pk)
                    || req.sender_pubkey.eq_ignore_ascii_case(&my_pk)
                {
                    return;
                }
                if !req.verify() {
                    tracing::debug!("Pedido de amizade com assinatura inválida descartado");
                    return;
                }
                let sender_pk = req.sender_pubkey.to_lowercase();
                let now = super::now_secs();
                if self.dm.firewall.is_blocked(&sender_pk, now) {
                    tracing::debug!("Pedido de amizade de {} ignorado pelo firewall", short_id(&sender_pk));
                    return;
                }
                let current_state = self.identity.get_friend_state(&sender_pk);
                let sender_nick = req.sender_nick.clone();
                if current_state == Some(FriendState::Confirmed) {
                    let _ = self.identity.update_friend_encryption_key(&req.encryption_advertisement);
                    self.persist_identity();
                    return;
                }
                let _ = self.identity.add_or_update_friend(&sender_pk, Some(&sender_nick), FriendState::PendingIncoming);
                let _ = self.identity.update_friend_encryption_key(&req.encryption_advertisement);
                self.persist_identity();
                self.emit(CoreEvent::FriendRequestReceived {
                    pubkey: sender_pk,
                    sender_nick,
                    message: req.message,
                    offline_delivery: false,
                });
                self.list_friends();
            }
            DmWireMessage::FriendResponse(resp) => {
                if !resp.recipient_pubkey.eq_ignore_ascii_case(&my_pk)
                    || resp.sender_pubkey.eq_ignore_ascii_case(&my_pk)
                {
                    return;
                }
                if !resp.verify() {
                    tracing::debug!("Resposta de amizade com assinatura inválida descartada");
                    return;
                }
                let sender_pk = resp.sender_pubkey.to_lowercase();
                let peer_name = self.friendly_name(&sender_pk);
                if resp.accepted {
                    let _ = self.identity.add_or_update_friend(&sender_pk, None, FriendState::Confirmed);
                    if let Some(ref adv) = resp.encryption_advertisement {
                        let _ = self.identity.update_friend_encryption_key(adv);
                    }
                    self.persist_identity();
                    self.dm.firewall.unblock(&sender_pk);
                    self.subscribe_dm_with(&sender_pk);
                    if self.is_pubkey_online(&sender_pk) {
                        self.send_ephemeral_key_offer(&sender_pk);
                        self.delegate_pending_to_friend(&sender_pk);
                    }
                    self.emit(CoreEvent::FriendRequestAccepted {
                        pubkey: sender_pk.clone(),
                        peer_name,
                        offline_delivery: false,
                    });
                    self.emit(CoreEvent::FriendUpdated {
                        pubkey: sender_pk,
                        alias: self.identity.get_friend(&resp.sender_pubkey).and_then(|f| f.alias.clone()),
                        removed: false,
                    });
                } else {
                    let _ = self.identity.set_friend_state(&sender_pk, FriendState::Rejected);
                    self.persist_identity();
                    self.emit(CoreEvent::FriendRequestRejected {
                        pubkey: sender_pk,
                        peer_name,
                        offline_delivery: false,
                    });
                }
                self.list_friends();
            }
            DmWireMessage::Message(envelope) => {
                if !envelope.recipient_pubkey.eq_ignore_ascii_case(&my_pk)
                    || envelope.sender_pubkey.eq_ignore_ascii_case(&my_pk)
                {
                    return;
                }
                let sender_pk = envelope.sender_pubkey.to_lowercase();
                let now = super::now_secs();
                let is_my_friend = self
                    .identity
                    .get_friends()
                    .iter()
                    .any(|f| f.public_key.eq_ignore_ascii_case(&sender_pk));
                let session_key = self
                    .dm
                    .sessions
                    .get(&sender_pk)
                    .and_then(|s| s.shared_session_key);
                let opened = envelope
                    .open(&self.identity, session_key.as_ref())
                    .or_else(|_| envelope.open(&self.identity, None));
                match opened {
                    Ok(payload) => {
                        let peer_name = self
                            .identity
                            .get_friends()
                            .iter()
                            .find(|f| f.public_key.eq_ignore_ascii_case(&sender_pk))
                            .and_then(|f| f.alias.clone())
                            .unwrap_or_else(|| payload.sender_nick.clone());

                        // Verifica no Firewall de DMs (política assimétrica: Carol decide se Alice é amiga DELA)
                        match self.dm.firewall.check_incoming_dm(
                            &sender_pk,
                            is_my_friend,
                            payload.text.len(),
                            false,
                            &self.dm.node_config.dm,
                            now,
                        ) {
                            DmFirewallVerdict::Allowed => {
                                self.emit(CoreEvent::DirectMessage {
                                    peer_pubkey: sender_pk,
                                    peer_name,
                                    author: payload.sender_nick,
                                    author_pubkey: payload.sender_pubkey,
                                    text: payload.text,
                                    timestamp: payload.timestamp,
                                    offline_delivery: false,
                                });
                            }
                            DmFirewallVerdict::DroppedSilently { .. } => {
                                tracing::debug!("DM de {} descartada silenciosamente pelo firewall", short_id(&sender_pk));
                            }
                            DmFirewallVerdict::NewlyBlocked {
                                reason,
                                duration_secs,
                                blocked_until,
                                offense_level,
                                send_courtesy,
                            } => {
                                self.emit(CoreEvent::PeerBlocked {
                                    pubkey: sender_pk.clone(),
                                    peer_name,
                                    is_friend: is_my_friend,
                                    reason: reason.clone(),
                                    duration_secs,
                                    blocked_until,
                                    offense_level,
                                    courtesy_sent: send_courtesy,
                                });
                                if send_courtesy {
                                    self.send_courtesy_block_notice(&sender_pk, &reason, duration_secs, now);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!("DM E2EE descartada de {}: {}", short_id(&sender_pk), e);
                    }
                }
            }
        }
    }

    /// Recebe mensagem do protocolo de Mailbox Offline (`MailboxMessage`)
    pub(super) fn on_mailbox_message(&mut self, msg: MailboxMessage) {
        let my_pk = self.my_pubkey();
        let now = super::now_secs();
        match msg {
            MailboxMessage::Store(envelope) => {
                // Se já sabemos que este envelope foi entregue (temos o ACK assinado), avisamos na malha para o remetente/guardião limpar!
                if let Some(ack) = self.dm.mailbox.get_ack(&envelope.envelope_id) {
                    self.publish_mailbox_ack(ack);
                    return;
                }
                // Se o envelope for para mim mesmo (eu estava online quando foi anunciado), recebo na hora!
                if envelope.recipient_pubkey.eq_ignore_ascii_case(&my_pk) {
                    self.receive_sealed_envelope(envelope, now);
                    return;
                }
                if envelope.sender_pubkey.eq_ignore_ascii_case(&my_pk) {
                    return;
                }
                // Verifica se o remetente (Alice) está na nossa lista de amigos
                let is_friend = self
                    .identity
                    .get_friends()
                    .iter()
                    .any(|f| f.public_key.eq_ignore_ascii_case(&envelope.sender_pubkey));
                let sender_name = self.friendly_name(&envelope.sender_pubkey);
                let recipient_short = short_id(&envelope.recipient_pubkey).to_string();
                let env_id = envelope.envelope_id.clone();
                let recipient_pk = envelope.recipient_pubkey.clone();
                let already_known = self.dm.mailbox.has_envelope_or_ack(&env_id);

                if let Ok(effective_ttl) =
                    self.dm
                        .mailbox
                        .store_for_friend(envelope, is_friend, &self.dm.node_config, now)
                {
                    if !already_known {
                        self.emit(CoreEvent::MailboxStoredForFriend {
                            sender_name,
                            recipient_short,
                            envelope_id: env_id,
                            effective_ttl_secs: effective_ttl,
                        });
                    }
                    // Se o destinatário já estiver conectado a nós agora, despacha imediatamente
                    if self.is_pubkey_online(&recipient_pk) {
                        self.deliver_pending_for(&recipient_pk);
                    }
                }
            }
            MailboxMessage::Deliver(envelope) => {
                if let Some(ack) = self.dm.mailbox.get_ack(&envelope.envelope_id) {
                    self.publish_mailbox_ack(ack);
                    return;
                }
                if envelope.recipient_pubkey.eq_ignore_ascii_case(&my_pk) {
                    self.receive_sealed_envelope(envelope, now);
                }
            }
            MailboxMessage::Ack(ack) => {
                if self.dm.mailbox.apply_ack(&ack) {
                    tracing::debug!("Envelope {} removido da mailbox após ACK", ack.envelope_id);
                }
            }
            MailboxMessage::KeyAdvertisement(ad) => {
                if ad.advertisement.user_id.eq_ignore_ascii_case(&my_pk) {
                    return;
                }
                if !ad.verify() {
                    tracing::debug!("Anúncio de chave de criptografia recebido via Mailbox inválido");
                    return;
                }
                let sender_pk = ad.advertisement.user_id.to_lowercase();
                if let Ok(updated) = self.identity.update_friend_encryption_key(&ad) {
                    if updated {
                        tracing::info!(peer = %sender_pk, epoch = ad.advertisement.epoch, "Chave de criptografia atualizada via rede de guardiões da Mailbox");
                        self.persist_identity();
                    }
                }
            }
        }
    }

    fn receive_sealed_envelope(&mut self, envelope: StoredEnvelope, now: u64) {
        let ack = self
            .dm
            .mailbox
            .get_ack(&envelope.envelope_id)
            .unwrap_or_else(|| ReceiptAck::new_signed(&self.identity, &envelope.envelope_id, now));
        if !self.dm.mailbox.mark_delivered_to_me(&envelope.envelope_id, ack.clone()) {
            // Envelope já foi entregue antes (mesmo em sessão anterior!); apenas reenvia o ACK para limpar o remetente/guardião atrasado
            self.publish_mailbox_ack(ack);
            return;
        }

        match envelope.unseal_and_verify(&self.identity) {
            Ok(payload) => {
                if payload.topic == FRIEND_REQUEST_MAILBOX_TOPIC {
                    let sender_pk = payload.sender_pubkey.to_lowercase();
                    if !self.dm.firewall.is_blocked(&sender_pk, now) {
                        let current_state = self.identity.get_friend_state(&sender_pk);
                        if current_state != Some(FriendState::Confirmed) {
                            let _ = self.identity.add_or_update_friend(&sender_pk, Some(&payload.sender_nick), FriendState::PendingIncoming);
                            self.persist_identity();
                            let msg = if payload.text.is_empty() { None } else { Some(payload.text) };
                            self.emit(CoreEvent::FriendRequestReceived {
                                pubkey: sender_pk,
                                sender_nick: payload.sender_nick,
                                message: msg,
                                offline_delivery: true,
                            });
                            self.list_friends();
                        }
                    }
                    self.publish_mailbox_ack(ack);
                    return;
                }

                if payload.topic == FRIEND_RESPONSE_MAILBOX_TOPIC {
                    let sender_pk = payload.sender_pubkey.to_lowercase();
                    let peer_name = self.friendly_name(&sender_pk);
                    if payload.text.trim().eq_ignore_ascii_case("ACCEPTED") {
                        let _ = self.identity.set_friend_state(&sender_pk, FriendState::Confirmed);
                        self.persist_identity();
                        self.dm.firewall.unblock(&sender_pk);
                        self.subscribe_dm_with(&sender_pk);
                        if self.is_pubkey_online(&sender_pk) {
                            self.send_ephemeral_key_offer(&sender_pk);
                            self.delegate_pending_to_friend(&sender_pk);
                        }
                        self.emit(CoreEvent::FriendRequestAccepted {
                            pubkey: sender_pk.clone(),
                            peer_name,
                            offline_delivery: true,
                        });
                        self.emit(CoreEvent::FriendUpdated {
                            pubkey: sender_pk,
                            alias: self.identity.get_friend(&payload.sender_pubkey).and_then(|f| f.alias.clone()),
                            removed: false,
                        });
                    } else {
                        let _ = self.identity.set_friend_state(&sender_pk, FriendState::Rejected);
                        self.persist_identity();
                        self.emit(CoreEvent::FriendRequestRejected {
                            pubkey: sender_pk,
                            peer_name,
                            offline_delivery: true,
                        });
                    }
                    self.list_friends();
                    self.publish_mailbox_ack(ack);
                    return;
                }

                let sender_pk = payload.sender_pubkey.to_lowercase();
                let is_my_friend = self
                    .identity
                    .get_friends()
                    .iter()
                    .any(|f| f.public_key.eq_ignore_ascii_case(&sender_pk));
                let peer_name = self
                    .identity
                    .get_friends()
                    .iter()
                    .find(|f| f.public_key.eq_ignore_ascii_case(&sender_pk))
                    .and_then(|f| f.alias.clone())
                    .unwrap_or_else(|| payload.sender_nick.clone());

                // Aplica o Firewall também para envelopes offline (evita que desconhecidos inundem a Carol via guardiões)
                match self.dm.firewall.check_incoming_dm(
                    &sender_pk,
                    is_my_friend,
                    payload.text.len(),
                    true,
                    &self.dm.node_config.dm,
                    now,
                ) {
                    DmFirewallVerdict::Allowed => {
                        self.emit(CoreEvent::DirectMessage {
                            peer_pubkey: sender_pk,
                            peer_name,
                            author: payload.sender_nick,
                            author_pubkey: payload.sender_pubkey,
                            text: payload.text,
                            timestamp: payload.timestamp,
                            offline_delivery: true,
                        });
                    }
                    DmFirewallVerdict::DroppedSilently { .. } => {
                        tracing::debug!("Envelope offline de {} descartado pelo firewall", short_id(&sender_pk));
                    }
                    DmFirewallVerdict::NewlyBlocked {
                        reason,
                        duration_secs,
                        blocked_until,
                        offense_level,
                        send_courtesy,
                    } => {
                        self.emit(CoreEvent::PeerBlocked {
                            pubkey: sender_pk.clone(),
                            peer_name,
                            is_friend: is_my_friend,
                            reason: reason.clone(),
                            duration_secs,
                            blocked_until,
                            offense_level,
                            courtesy_sent: send_courtesy,
                        });
                        if send_courtesy && self.is_pubkey_online(&sender_pk) {
                            self.send_courtesy_block_notice(&sender_pk, &reason, duration_secs, now);
                        }
                    }
                }
                // Mesmo se bloqueado, envia ACK para que os guardiões limpem o envelope do disco deles
                self.publish_mailbox_ack(ack);
            }
            Err(e) => {
                tracing::debug!("Envelope offline inválido descartado: {}", e);
            }
        }
    }

    /// Envia 1 única mensagem de cortesia E2EE avisando o remetente de que ele foi bloqueado temporariamente pelo firewall local
    fn send_courtesy_block_notice(&mut self, recipient_pubkey: &str, reason: &str, duration_secs: u64, _now: u64) {
        let topic_str = self.subscribe_dm_with(recipient_pubkey);
        let courtesy_text = format!(
            "🛡️ [Aviso Automático do Firewall de {}]: Suas mensagens diretas foram temporariamente limitadas por {} ({}). Caso seja um engano, aguarde ou peça para {} te adicionar aos amigos.",
            self.nick,
            format_duration(Some(duration_secs)),
            reason,
            self.nick
        );
        // Usa Sealed Box direto (None para session_key) para que mesmo um desconhecido sem handshake de sessão completo decifre na hora!
        if let Ok(envelope) = DirectMessageEnvelope::seal(
            &self.identity,
            recipient_pubkey,
            &courtesy_text,
            super::now_millis(),
            None,
        ) {
            let wire_msg = DmWireMessage::Message(envelope);
            let bytes = wire::encode(&wire_msg);
            let _ = self.publish_gossip(IdentTopic::new(topic_str), bytes);
        }
    }

    fn publish_mailbox_ack(&mut self, ack: ReceiptAck) {
        let msg = MailboxMessage::Ack(ack);
        let bytes = wire::encode(&msg);
        let _ = self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes);
    }

    /// Chamado quando um par Anarchord é identificado no Swarm:
    /// 1. Se tínhamos envelopes guardados para ele (`recipient == pubkey`), entregamos.
    /// 2. Se ele é nosso amigo (`pubkey` está nos amigos), delegamos envelopes da nossa outbox para ele guardar e enviamos KeyOffer de DM.
    pub(super) fn on_peer_identified_dm_and_mailbox(&mut self, peer_pubkey: &str) {
        let clean_pk = peer_pubkey.trim().to_lowercase();
        let is_friend = self
            .identity
            .get_friends()
            .iter()
            .any(|f| f.public_key.eq_ignore_ascii_case(&clean_pk));

        // Garante que estamos inscritos no tópico determinístico de DM com qualquer par Anarchord identificado
        self.subscribe_dm_with(&clean_pk);

        if is_friend {
            self.send_ephemeral_key_offer(&clean_pk);
            self.delegate_pending_to_friend(&clean_pk);
            // Propaga ACKs assinados que já recebemos para limpar a outbox/mailbox do amigo que estava offline
            for ack in self.dm.mailbox.known_acks() {
                self.publish_mailbox_ack(ack);
            }
        }

        // Entrega oportunista se guardamos envelopes destinados a este par (mesmo sem ser nosso amigo!)
        self.deliver_pending_for(&clean_pk);
    }

    /// Verifica se o par `pubkey` está conectado E já anunciou inscrição no tópico `MAILBOX_TOPIC` do Gossipsub
    fn is_peer_subscribed_to_mailbox(&self, pubkey: &str) -> bool {
        let mailbox_hash = IdentTopic::new(MAILBOX_TOPIC).hash();
        self.node
            .swarm
            .behaviour()
            .gossipsub
            .all_peers()
            .filter(|(_, topics)| topics.contains(&&mailbox_hash))
            .any(|(peer, _)| {
                self.peer_metadata
                    .get(peer)
                    .map(|(_, pk)| pk.eq_ignore_ascii_case(pubkey))
                    .or_else(|| {
                        crate::api::pubkey_hex_from_peer_id(peer)
                            .map(|pk| pk.eq_ignore_ascii_case(pubkey))
                    })
                    .unwrap_or(false)
            })
    }

    /// Orientado a eventos: quando um amigo `friend_pubkey` fica online (e está inscrito em `MAILBOX_TOPIC`),
    /// Alice verifica quais envelopes da sua outbox ainda NÃO foram pedidos para esse amigo guardar,
    /// publica `MailboxMessage::Store` uma única vez e registra que já pediu para esse amigo!
    pub(super) fn delegate_pending_to_friend(&mut self, friend_pubkey: &str) {
        let clean_friend = friend_pubkey.trim().to_lowercase();
        let is_friend = self
            .identity
            .get_friends()
            .iter()
            .any(|f| f.public_key.eq_ignore_ascii_case(&clean_friend));
        if !is_friend || !self.is_peer_subscribed_to_mailbox(&clean_friend) {
            return;
        }
        let my_pk = self.my_pubkey();
        let undelegated = self.dm.mailbox.undelegated_for_guardian(
            &my_pk,
            &clean_friend,
            super::now_secs(),
        );
        for env in undelegated {
            let env_id = env.envelope_id.clone();
            let msg = MailboxMessage::Store(env);
            let bytes = wire::encode(&msg);
            if self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes).is_ok() {
                self.dm
                    .mailbox
                    .mark_delegated_to_guardian(&env_id, &clean_friend);
            }
        }
    }

    /// Chamado quando um par se inscreve no tópico `MAILBOX_TOPIC` do Gossipsub:
    /// como o `Subscribed` do Gossipsub geralmente chega alguns milissegundos *depois* do `Identify`,
    /// decidimos de forma orientada a eventos se esse par é nosso amigo (e ainda não recebeu a delegação)
    /// ou se é o destinatário de algum envelope que estamos guardando!
    pub(super) fn on_peer_subscribed_mailbox(&mut self, peer_id: libp2p::PeerId) {
        let peer_pk = self
            .peer_metadata
            .get(&peer_id)
            .map(|(_, pk)| pk.clone())
            .or_else(|| crate::api::pubkey_hex_from_peer_id(&peer_id));
        if let Some(pk) = peer_pk {
            self.delegate_pending_to_friend(&pk);
            self.deliver_pending_for(&pk);
        }
        for ack in self.dm.mailbox.known_acks() {
            self.publish_mailbox_ack(ack);
        }
    }

    pub(super) fn deliver_pending_for(&mut self, recipient_pubkey: &str) {
        if !self.is_peer_subscribed_to_mailbox(recipient_pubkey) {
            return;
        }
        let now = super::now_secs();
        let pending = self.dm.mailbox.pending_for_recipient(recipient_pubkey, now);
        for env in pending {
            let msg = MailboxMessage::Deliver(env);
            let bytes = wire::encode(&msg);
            let _ = self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes);
        }
    }

    /// Tick periódico da Mailbox: apenas purga envelopes expirados do disco (sem inundar a rede com republicações!)
    pub(super) fn mailbox_tick(&mut self) {
        let now = super::now_secs();
        self.dm.mailbox.purge_expired(now);
    }

    /// Exibe a configuração atual e o uso da mailbox
    pub(super) fn show_config(&self) {
        self.emit(CoreEvent::ConfigStatus {
            config: self.dm.node_config.clone(),
            mailbox_used_bytes: self.dm.mailbox.total_bytes(),
            mailbox_envelope_count: self.dm.mailbox.envelope_count(),
        });
    }

    /// Altera um parâmetro da configuração local e persiste no disco
    pub(super) fn set_config(&mut self, key: &str, value: &str) {
        match self.dm.node_config.set_key(key, value) {
            Ok(()) => {
                let _ = self.dm.node_config.save(self.dm.config_path.as_deref());
                self.emit(CoreEvent::ConfigUpdated {
                    key: key.trim().to_string(),
                    value: value.trim().to_string(),
                });
                self.show_config();
            }
            Err(e) => self.error(CoreError::Config(e.to_string())),
        }
    }

    /// Lista os bloqueios ativos no Firewall local (`/firewall`)
    pub(super) fn list_firewall(&self) {
        let blocks = self.dm.firewall.active_blocks(super::now_secs());
        self.emit(CoreEvent::FirewallStatus(blocks));
    }

    /// Desbloqueia manualmente um par no Firewall local (`/firewall unblock <par>`)
    pub(super) fn unblock_peer(&mut self, target: &str) {
        let pubkey = self
            .resolve_dm_target(target)
            .map(|(pk, _)| pk)
            .unwrap_or_else(|| target.trim().to_lowercase());
        let peer_name = self.friendly_name(&pubkey);
        if self.dm.firewall.unblock(&pubkey) {
            self.emit(CoreEvent::PeerUnblocked { pubkey, peer_name });
        } else {
            self.error(CoreError::Friend(format!("'{}' não está bloqueado no firewall", target)));
        }
    }

    /// Envia pedido de amizade mútuo (online via DM topic ou offline via Guardiões)
    pub(super) fn send_friend_request(&mut self, who: &str, alias: Option<&str>, message: Option<&str>) {
        let (pubkey, inferred_alias) = match self.resolve_dm_target(who) {
            Some((pk, name)) => {
                let alias_opt = alias.map(str::to_string).or_else(|| {
                    if !pk.eq_ignore_ascii_case(&name) {
                        Some(name)
                    } else {
                        None
                    }
                });
                (pk, alias_opt)
            }
            None => {
                let who_trim = who.trim();
                if who_trim.len() == 64 && who_trim.chars().all(|c| c.is_ascii_hexdigit()) {
                    (who_trim.to_lowercase(), alias.map(str::to_string))
                } else {
                    return self.error(CoreError::PeerNotFound(who.to_string()));
                }
            }
        };

        if pubkey.eq_ignore_ascii_case(&self.my_pubkey()) {
            return self.error(CoreError::Friend("Você não pode adicionar a si mesmo como amigo".into()));
        }

        // Se já tínhamos um pedido recebido pendente deste par, adicionar significa aceitar!
        if self.identity.get_friend_state(&pubkey) == Some(FriendState::PendingIncoming) {
            self.accept_friend(&pubkey);
            return;
        }

        let now = super::now_secs();
        let now_ms = super::now_millis();

        // 1. Registra localmente como PendingOutgoing
        if let Err(e) = self.identity.add_or_update_friend(&pubkey, inferred_alias.as_deref(), FriendState::PendingOutgoing) {
            return self.error(CoreError::Friend(e.to_string()));
        }
        self.persist_identity();
        self.dm.firewall.unblock(&pubkey);
        self.subscribe_dm_with(&pubkey);

        // 2. Envia online via tópico mútuo
        let req = FriendRequest::new_signed(&self.identity, &pubkey, message, now);
        let dm_top = IdentTopic::new(dm_topic(&self.my_pubkey(), &pubkey));
        let wire_msg = wire::encode(&DmWireMessage::FriendRequest(req));
        let _ = self.publish_gossip(dm_top, wire_msg);

        if self.is_pubkey_online(&pubkey) {
            self.send_ephemeral_key_offer(&pubkey);
            self.delegate_pending_to_friend(&pubkey);
        }

        // 3. Enfileira na Mailbox para entrega offline via Guardiões caso o par esteja offline
        let intro_msg = message.unwrap_or("");
        if let Ok(stored) = StoredEnvelope::create_signed_and_sealed_topic(
            &self.identity,
            &pubkey,
            FRIEND_REQUEST_MAILBOX_TOPIC,
            intro_msg,
            now_ms,
            None,
        ) {
            let env_id = stored.envelope_id.clone();
            self.dm.mailbox.insert_own(stored.clone(), &self.dm.node_config, now);
            let msg = MailboxMessage::Store(stored);
            let bytes = wire::encode(&msg);
            if self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes).is_ok() {
                let mailbox_hash = IdentTopic::new(MAILBOX_TOPIC).hash();
                let subscribed_friends: Vec<String> = self
                    .node
                    .swarm
                    .behaviour()
                    .gossipsub
                    .all_peers()
                    .filter(|(_, topics)| topics.contains(&&mailbox_hash))
                    .filter_map(|(peer, _)| self.peer_metadata.get(peer).map(|(_, pk)| pk.to_lowercase()))
                    .filter(|pk| {
                        self.identity
                            .get_friends()
                            .iter()
                            .any(|f| f.public_key.eq_ignore_ascii_case(pk))
                    })
                    .collect();
                for friend_pk in subscribed_friends {
                    self.dm.mailbox.mark_delegated_to_guardian(&env_id, &friend_pk);
                }
            }
        }

        self.emit(CoreEvent::FriendUpdated {
            pubkey: pubkey.to_lowercase(),
            alias: inferred_alias,
            removed: false,
        });
        self.list_friends();
    }

    /// Aceita um pedido de amizade pendente
    pub(super) fn accept_friend(&mut self, target: &str) {
        let (pubkey, _) = match self.resolve_dm_target(target) {
            Some(res) => res,
            None => {
                let t_trim = target.trim();
                if t_trim.len() == 64 && t_trim.chars().all(|c| c.is_ascii_hexdigit()) {
                    (t_trim.to_lowercase(), t_trim.to_string())
                } else {
                    return self.error(CoreError::Friend(format!("Contato '{}' não encontrado para aceitar", target)));
                }
            }
        };

        let now = super::now_secs();
        let now_ms = super::now_millis();

        if !self.identity.set_friend_state(&pubkey, FriendState::Confirmed) {
            let _ = self.identity.add_or_update_friend(&pubkey, None, FriendState::Confirmed);
        }
        self.persist_identity();
        self.dm.firewall.unblock(&pubkey);
        self.subscribe_dm_with(&pubkey);

        // Envia resposta positiva online
        let resp = FriendResponse::new_signed(&self.identity, &pubkey, true, now);
        let dm_top = IdentTopic::new(dm_topic(&self.my_pubkey(), &pubkey));
        let wire_msg = wire::encode(&DmWireMessage::FriendResponse(resp));
        let _ = self.publish_gossip(dm_top, wire_msg);

        if self.is_pubkey_online(&pubkey) {
            self.send_ephemeral_key_offer(&pubkey);
            self.delegate_pending_to_friend(&pubkey);
        }

        // Também despacha via Mailbox para entrega offline garantida
        if let Ok(stored) = StoredEnvelope::create_signed_and_sealed_topic(
            &self.identity,
            &pubkey,
            FRIEND_RESPONSE_MAILBOX_TOPIC,
            "ACCEPTED",
            now_ms,
            None,
        ) {
            self.dm.mailbox.insert_own(stored.clone(), &self.dm.node_config, now);
            let msg = MailboxMessage::Store(stored);
            let bytes = wire::encode(&msg);
            let _ = self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes);
        }

        self.emit(CoreEvent::FriendUpdated {
            pubkey: pubkey.clone(),
            alias: self.identity.get_friend(&pubkey).and_then(|f| f.alias.clone()),
            removed: false,
        });
        self.list_friends();
    }

    /// Rejeita um pedido de amizade pendente
    pub(super) fn reject_friend(&mut self, target: &str) {
        let (pubkey, _) = match self.resolve_dm_target(target) {
            Some(res) => res,
            None => {
                let t_trim = target.trim();
                if t_trim.len() == 64 && t_trim.chars().all(|c| c.is_ascii_hexdigit()) {
                    (t_trim.to_lowercase(), t_trim.to_string())
                } else {
                    return self.error(CoreError::Friend(format!("Contato '{}' não encontrado para rejeitar", target)));
                }
            }
        };

        let now = super::now_secs();
        let now_ms = super::now_millis();

        let _ = self.identity.set_friend_state(&pubkey, FriendState::Rejected);
        self.persist_identity();

        let _peer_name = self.friendly_name(&pubkey);

        // Envia resposta de rejeição online
        let resp = FriendResponse::new_signed(&self.identity, &pubkey, false, now);
        let dm_top = IdentTopic::new(dm_topic(&self.my_pubkey(), &pubkey));
        let wire_msg = wire::encode(&DmWireMessage::FriendResponse(resp));
        let _ = self.publish_gossip(dm_top, wire_msg);

        // Despacha via Mailbox para entrega offline
        if let Ok(stored) = StoredEnvelope::create_signed_and_sealed_topic(
            &self.identity,
            &pubkey,
            FRIEND_RESPONSE_MAILBOX_TOPIC,
            "REJECTED",
            now_ms,
            None,
        ) {
            self.dm.mailbox.insert_own(stored.clone(), &self.dm.node_config, now);
            let msg = MailboxMessage::Store(stored);
            let bytes = wire::encode(&msg);
            let _ = self.publish_gossip(IdentTopic::new(MAILBOX_TOPIC), bytes);
        }

        self.emit(CoreEvent::FriendUpdated {
            pubkey: pubkey.clone(),
            alias: self.identity.get_friend(&pubkey).and_then(|f| f.alias.clone()),
            removed: false,
        });
        self.list_friends();
    }

    /// Reenvia pedido de amizade a um contato
    pub(super) fn resend_friend_request(&mut self, target: &str, message: Option<&str>) {
        self.send_friend_request(target, None, message);
    }
}
