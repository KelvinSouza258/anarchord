//! Runtime de Mensagens Diretas (DM 1:1 E2EE), Sessões Efêmeras e Mailbox Offline.

use super::{CoreError, CoreEvent, Runtime};
use crate::community::short_id;
use crate::config::NodeConfig;
use crate::dm::{
    dm_topic, DirectMessageEnvelope, DmPeerSession, DmWireMessage, EphemeralKeyOffer,
    MailboxMessage, MailboxStore, ReceiptAck, StoredEnvelope, MAILBOX_TOPIC,
};
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
        let _ = self
            .node
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(IdentTopic::new(topic_str), bytes);
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
                now,
                session_key.as_ref(),
            ) {
                Ok(envelope) => {
                    let wire_msg = DmWireMessage::Message(envelope);
                    let bytes = wire::encode(&wire_msg);
                    let _ = self
                        .node
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(IdentTopic::new(topic_str), bytes);
                    self.emit(CoreEvent::DirectMessage {
                        peer_pubkey: peer_pk,
                        peer_name,
                        author: self.nick.clone(),
                        author_pubkey: self.my_pubkey(),
                        text: text.to_string(),
                        timestamp: now,
                        offline_delivery: false,
                    });
                }
                Err(e) => self.error(CoreError::Friend(e.to_string())),
            }
        } else {
            // Destinatário offline: cria StoredEnvelope Sign-then-Seal e delega aos amigos guardiões
            match StoredEnvelope::create_signed_and_sealed(
                &self.identity,
                &peer_pk,
                text,
                now,
                suggested_ttl,
            ) {
                Ok(stored) => {
                    let env_id = stored.envelope_id.clone();
                    self.dm
                        .mailbox
                        .insert_own(stored.clone(), &self.dm.node_config, now);
                    let msg = MailboxMessage::Store(stored);
                    let bytes = wire::encode(&msg);
                    let _ = self
                        .node
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(IdentTopic::new(MAILBOX_TOPIC), bytes);

                    self.emit(CoreEvent::DirectMessage {
                        peer_pubkey: peer_pk.clone(),
                        peer_name: peer_name.clone(),
                        author: self.nick.clone(),
                        author_pubkey: self.my_pubkey(),
                        text: text.to_string(),
                        timestamp: now,
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
            DmWireMessage::Message(envelope) => {
                if !envelope.recipient_pubkey.eq_ignore_ascii_case(&my_pk)
                    || envelope.sender_pubkey.eq_ignore_ascii_case(&my_pk)
                {
                    return;
                }
                let sender_pk = envelope.sender_pubkey.to_lowercase();
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

                if let Ok(effective_ttl) =
                    self.dm
                        .mailbox
                        .store_for_friend(envelope, is_friend, &self.dm.node_config, now)
                {
                    self.emit(CoreEvent::MailboxStoredForFriend {
                        sender_name,
                        recipient_short,
                        envelope_id: env_id,
                        effective_ttl_secs: effective_ttl,
                    });
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
        }
    }

    fn receive_sealed_envelope(&mut self, envelope: StoredEnvelope, now: u64) {
        let ack = self
            .dm
            .mailbox
            .get_ack(&envelope.envelope_id)
            .unwrap_or_else(|| ReceiptAck::new_signed(&self.identity, &envelope.envelope_id, now));
        if !self.dm.mailbox.mark_delivered_to_me(&envelope.envelope_id, envelope.expires_at, ack.clone()) {
            // Envelope já foi entregue antes (mesmo em sessão anterior!); apenas reenvia o ACK para limpar o remetente/guardião atrasado
            self.publish_mailbox_ack(ack);
            return;
        }
        match envelope.unseal_and_verify(&self.identity) {
            Ok(payload) => {
                let sender_pk = payload.sender_pubkey.to_lowercase();
                let peer_name = self
                    .identity
                    .get_friends()
                    .iter()
                    .find(|f| f.public_key.eq_ignore_ascii_case(&sender_pk))
                    .and_then(|f| f.alias.clone())
                    .unwrap_or_else(|| payload.sender_nick.clone());
                self.emit(CoreEvent::DirectMessage {
                    peer_pubkey: sender_pk,
                    peer_name,
                    author: payload.sender_nick,
                    author_pubkey: payload.sender_pubkey,
                    text: payload.text,
                    timestamp: payload.timestamp,
                    offline_delivery: true,
                });
                self.publish_mailbox_ack(ack);
            }
            Err(e) => {
                tracing::debug!("Envelope offline inválido descartado: {}", e);
            }
        }
    }

    fn publish_mailbox_ack(&mut self, ack: ReceiptAck) {
        let msg = MailboxMessage::Ack(ack);
        let bytes = wire::encode(&msg);
        let _ = self
            .node
            .swarm
            .behaviour_mut()
            .gossipsub
            .publish(IdentTopic::new(MAILBOX_TOPIC), bytes);
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
            // Delega envelopes nossos pendentes para o amigo que acabou de ficar online
            let my_pk = self.my_pubkey();
            let my_pending = self.dm.mailbox.pending_from_sender(&my_pk, super::now_secs());
            for env in my_pending {
                let msg = MailboxMessage::Store(env);
                let bytes = wire::encode(&msg);
                let _ = self
                    .node
                    .swarm
                    .behaviour_mut()
                    .gossipsub
                    .publish(IdentTopic::new(MAILBOX_TOPIC), bytes);
            }
            // Propaga ACKs assinados que já recebemos para limpar a outbox/mailbox do amigo que estava offline
            for ack in self.dm.mailbox.known_acks() {
                self.publish_mailbox_ack(ack);
            }
        }

        // Entrega oportunista se guardamos envelopes destinados a este par (mesmo sem ser nosso amigo!)
        self.deliver_pending_for(&clean_pk);
    }

    pub(super) fn deliver_pending_for(&mut self, recipient_pubkey: &str) {
        let now = super::now_secs();
        let pending = self.dm.mailbox.pending_for_recipient(recipient_pubkey, now);
        for env in pending {
            let msg = MailboxMessage::Deliver(env);
            let bytes = wire::encode(&msg);
            let _ = self
                .node
                .swarm
                .behaviour_mut()
                .gossipsub
                .publish(IdentTopic::new(MAILBOX_TOPIC), bytes);
        }
    }

    /// Tick periódico da Mailbox: purga envelopes expirados e reanuncia entregas pendentes para destinatários conectados
    pub(super) fn mailbox_tick(&mut self) {
        let now = super::now_secs();
        self.dm.mailbox.purge_expired(now);

        let online_pks: Vec<String> = self
            .peer_metadata
            .iter()
            .filter(|(peer, _)| self.connected_peers.contains(peer))
            .map(|(_, (_, pk))| pk.to_lowercase())
            .collect();

        for pk in online_pks {
            self.deliver_pending_for(&pk);
        }
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
}
