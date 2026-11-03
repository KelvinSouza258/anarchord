//! Servidores: comandos, cadeia de configuração, moderação e o grupo cifrado (MLS).

use super::{
    ChannelInfo, CoreError, CoreEvent, Role, Runtime, ServerChange, ServerCommand, ServerInfo, ServerListEntry, ServerNotice,
};
use crate::api::ChatMessage;
use crate::community::{
    self,
    e2ee::{self, CommitOutcome, E2eeError},
    server_control_topic, server_dht_key, ChannelType, CommunityError, ModKind, ServerEvent, ServerMessage, Space,
};
use libp2p::gossipsub::IdentTopic;

/// Texto do convite publicado no chat. Quem recebe usa `/server accept`.
pub fn invite_text(server_name: &str, server_id: &str) -> String {
    format!("📨 Convite para o servidor '{}'. Para entrar: /server accept  (ou /server join {})", server_name, server_id)
}

/// Se a mensagem de chat contém um convite (`/server join <id>`), devolve o id do servidor
pub fn parse_invite(text: &str) -> Option<String> {
    let rest = text.split("/server join ").nth(1)?;
    let id: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    community::is_valid_server_id(&id).then_some(id)
}

impl Runtime {
    fn notice(&self, notice: ServerNotice) {
        self.emit(CoreEvent::Server(notice));
    }

    /// Passa a ouvir o tópico de controle do servidor (cadeia e moderação) e o de telas dele
    pub(super) fn follow_server(&mut self, server_id: &str) {
        let gossipsub = &mut self.node.swarm.behaviour_mut().gossipsub;
        let _ = gossipsub.subscribe(&IdentTopic::new(server_control_topic(server_id)));
        let _ = gossipsub.subscribe(&IdentTopic::new(community::screen_topic(&Space::Server(server_id.to_string()))));
    }

    /// Publica no tópico de controle do servidor. Falha (sem ninguém no tópico) é normal e ignorada.
    pub(super) fn publish_server_message(&mut self, server_id: &str, message: &ServerMessage) -> bool {
        let topic = IdentTopic::new(server_control_topic(server_id));
        self.node.swarm.behaviour_mut().gossipsub.publish(topic, crate::wire::encode(message)).is_ok()
    }

    fn default_channel(&self, server_id: &str) -> String {
        self.servers.get(server_id).and_then(|s| s.default_text_channel()).unwrap_or_else(|| "geral".to_string())
    }

    fn enter_server(&mut self, server_id: String) {
        let channel = self.default_channel(&server_id);
        self.enter_channel(Space::Server(server_id), channel);
    }

    /// Pubkey de um par por nick, prefixo da pubkey (6+ caracteres) ou a pubkey completa
    fn resolve_pubkey(&self, query: &str) -> Option<String> {
        if community::is_valid_server_id(query) {
            return Some(query.to_string());
        }
        self.peer_metadata
            .values()
            .find(|(nick, pubkey)| nick.eq_ignore_ascii_case(query) || (query.len() >= 6 && pubkey.starts_with(query)))
            .map(|(_, pubkey)| pubkey.clone())
    }

    /// Ciclo periódico: pede cadeias que faltam, cuida do grupo cifrado e da manutenção do dono
    pub(super) fn server_sync_tick(&mut self) {
        for id in self.servers.list().filter(|s| !s.has_chain()).map(|s| s.server_id.clone()).collect::<Vec<_>>() {
            if let Some(request) = self.servers.chain_request(&id) {
                self.publish_server_message(&id, &request);
            }
        }
        let now = super::now_secs();
        // Grupo cifrado: o dono cria, admite e remove; quem não tem a chave pede entrada (no máximo a cada 15 s)
        let ids: Vec<(String, bool)> = self.servers.list().filter(|s| s.has_chain()).map(|s| (s.server_id.clone(), s.is_owner())).collect();
        for (id, owner) in ids {
            if owner {
                if !self.mls.has_group(&id) {
                    let _ = self.mls.create_group(&id);
                }
                if let Ok(Some(commit)) = e2ee::enforce_membership(&mut self.mls, &self.servers, &id, now) {
                    self.publish_server_message(&id, &commit);
                }
            } else if !self.mls.has_group(&id)
                && self.last_key_package.get(&id).is_none_or(|t| t.elapsed() >= std::time::Duration::from_secs(15))
            {
                if let Ok(key_package) = self.mls.key_package() {
                    if self.publish_server_message(&id, &ServerMessage::KeyPackage { server_id: id.clone(), key_package }) {
                        self.last_key_package.insert(id, std::time::Instant::now());
                    }
                }
            }
        }
        // Dono online: consolida ações de moderadores e renova certificados na janela
        for id in self.servers.list().filter(|s| s.is_owner()).map(|s| s.server_id.clone()).collect::<Vec<_>>() {
            if let Some(block) = self.servers.owner_maintenance(&id, now) {
                self.publish_server_message(&id, &block);
                if self.active.server_id() == Some(id.as_str()) {
                    self.refresh_space();
                }
            }
        }
    }

    /// Entra (ou volta) num servidor pelo id. Sem a cadeia ainda, pede aos membros e entra quando chegar.
    fn join_server(&mut self, server_id: &str) {
        if let Err(e) = self.servers.join(server_id) {
            return self.error(CoreError::Server(e.to_string()));
        }
        self.follow_server(server_id);
        if self.servers.get(server_id).is_some_and(|s| s.has_chain()) {
            self.enter_server(server_id.to_string());
        } else {
            self.pending_switch = Some(server_id.to_string());
            self.node.dht_find(server_dht_key(server_id));
            if let Some(request) = self.servers.chain_request(server_id) {
                self.publish_server_message(server_id, &request);
            }
            self.notice(ServerNotice::Searching { id: server_id.to_string() });
        }
    }

    /// Publica uma alteração bem-sucedida e atualiza o espaço
    fn publish_change(&mut self, id: &str, result: Result<ServerMessage, CommunityError>, change: ServerChange) {
        match result {
            Ok(message) => {
                self.publish_server_message(id, &message);
                self.refresh_space();
                self.notice(ServerNotice::Changed { server: self.server_name(id), change });
            }
            Err(e) => self.error(CoreError::Server(e.to_string())),
        }
    }

    fn server_name(&self, id: &str) -> String {
        self.servers.get(id).map(|s| s.name()).unwrap_or_else(|| community::short_id(id).to_string())
    }

    pub(super) fn run_server_command(&mut self, command: ServerCommand) {
        let now = super::now_secs();
        let current = self.active.server_id().map(str::to_string);
        // Comandos que só fazem sentido dentro de um servidor
        macro_rules! need_server {
            () => {
                match current.clone() {
                    Some(id) => id,
                    None => return self.error(CoreError::InLobby),
                }
            };
        }
        macro_rules! need_peer {
            ($target:expr) => {
                match self.resolve_pubkey(&$target) {
                    Some(pubkey) => pubkey,
                    None => return self.error(CoreError::PeerNotFound($target.to_string())),
                }
            };
        }

        match command {
            ServerCommand::Help => self.notice(ServerNotice::Help),
            ServerCommand::Create(name) => match self.servers.create(&name, &self.my_pubkey(), now) {
                Ok(id) => {
                    self.follow_server(&id);
                    if let Err(e) = self.mls.create_group(&id) {
                        tracing::warn!("Grupo cifrado não criado: {}", e);
                    }
                    self.notice(ServerNotice::Created { id: id.clone(), name });
                    self.enter_server(id);
                }
                Err(e) => self.error(CoreError::Server(e.to_string())),
            },
            ServerCommand::Join(id) => self.join_server(id.trim()),
            ServerCommand::Accept => match self.last_invite.clone() {
                Some(id) => self.join_server(&id),
                None => self.error(CoreError::NoInvite),
            },
            ServerCommand::Leave => {
                let id = need_server!();
                let name = self.server_name(&id);
                let was_owner = self.servers.get(&id).is_some_and(|s| s.is_owner());
                self.servers.leave(&id);
                self.mls.drop_group(&id);
                let gossipsub = &mut self.node.swarm.behaviour_mut().gossipsub;
                let _ = gossipsub.unsubscribe(&IdentTopic::new(server_control_topic(&id)));
                let _ = gossipsub.unsubscribe(&IdentTopic::new(community::screen_topic(&Space::Server(id.clone()))));
                self.enter_channel(Space::Lobby, "geral".to_string());
                self.notice(ServerNotice::Left { name, was_owner });
            }
            ServerCommand::List => {
                let me = self.my_pubkey();
                let servers = self
                    .servers
                    .list()
                    .map(|s| ServerListEntry {
                        id: s.server_id.clone(),
                        name: s.name(),
                        current: current.as_deref() == Some(s.server_id.as_str()),
                        owner: s.is_owner(),
                        moderator_level: if s.is_owner() { None } else { s.level_of(&me, now) },
                        pending: !s.has_chain(),
                        closed: s.has_chain() && s.chain().state().closed,
                        banned: s.has_chain() && s.is_banned(&me, now),
                    })
                    .collect();
                self.notice(ServerNotice::List { lobby_current: current.is_none(), servers });
            }
            ServerCommand::Info => {
                let id = need_server!();
                let Some(server) = self.servers.get(&id) else { return };
                let state = server.effective_state(now);
                let head = server.chain().head();
                let me = self.my_pubkey();
                let role = match state.level_of(&me, now) {
                    Some(0) => Role::Owner,
                    Some(level) => Role::Moderator(level),
                    None if server.is_owner() => Role::Owner,
                    None => Role::Member,
                };
                let info = ServerInfo {
                    id: id.clone(),
                    name: server.name(),
                    height: head.map_or(0, |b| b.body.height),
                    updated_at: head.map(|b| b.body.timestamp),
                    channels: server.channels().into_iter().map(|c| ChannelInfo { voice: c.channel_type == ChannelType::Voice, name: c.name }).collect(),
                    role,
                    closed: state.closed,
                    allow_list: state.allow_list.len(),
                    moderators: state.moderators(now).iter().map(|(pk, level, until)| (self.nick_for(pk), *level, *until)).collect(),
                    bans: state.active_bans(now).iter().map(|(pk, ban)| (self.nick_for(pk), ban.until, ban.by_level)).collect(),
                    cert_validity_secs: state.cert_validity_secs,
                    renewal_window_secs: state.renewal_window_secs,
                    pending_actions: server.pending_actions().count(),
                };
                self.notice(ServerNotice::Info(info));
            }
            ServerCommand::History => {
                let id = need_server!();
                let history = self.servers.history(&id);
                self.notice(ServerNotice::History(history));
            }
            ServerCommand::Switch(query) => {
                if query.eq_ignore_ascii_case("lobby") {
                    return self.enter_channel(Space::Lobby, "geral".to_string());
                }
                match self.servers.find(&query).map(|s| (s.server_id.clone(), s.has_chain())) {
                    Some((id, true)) => self.enter_server(id),
                    Some((id, false)) => {
                        self.pending_switch = Some(id.clone());
                        self.notice(ServerNotice::WaitingConfig { id });
                    }
                    None => self.error(CoreError::ServerNotFound(query)),
                }
            }
            ServerCommand::Invite => {
                let id = need_server!();
                let name = self.server_name(&id);
                let invite = ChatMessage::new_signed(&self.identity, "geral", &invite_text(&name, &id), now);
                let lobby = IdentTopic::new(community::channel_topic(&Space::Lobby, "geral"));
                let sent = self.node.swarm.behaviour_mut().gossipsub.publish(lobby, crate::wire::encode(&invite)).is_ok();
                self.notice(if sent { ServerNotice::InviteSent { server: name } } else { ServerNotice::InviteManual { id: id.clone() } });
                if self.servers.get(&id).is_some_and(|s| s.chain().state().closed) {
                    self.notice(ServerNotice::InviteNeedsAllow);
                }
            }
            ServerCommand::AddChannel { name, voice } => {
                let id = need_server!();
                let kind = if voice { ChannelType::Voice } else { ChannelType::Text };
                let result = self.servers.add_channel(&id, &name, kind, now);
                self.publish_change(&id, result, ServerChange::ChannelAdded { name, voice });
            }
            ServerCommand::RemoveChannel(name) => {
                let id = need_server!();
                let result = self.servers.remove_channel(&id, &name, now);
                self.publish_change(&id, result, ServerChange::ChannelRemoved(name));
            }
            ServerCommand::AddModerator { target, level } => {
                let id = need_server!();
                let pubkey = need_peer!(target);
                let validity_secs = self.servers.get(&id).map_or(0, |s| s.chain().state().cert_validity_secs);
                let result = self.servers.add_moderator(&id, &pubkey, level, now);
                let who = self.nick_for(&pubkey);
                self.publish_change(&id, result, ServerChange::ModeratorAdded { who, level, validity_secs });
            }
            ServerCommand::RemoveModerator(target) => {
                let id = need_server!();
                let pubkey = need_peer!(target);
                let result = self.servers.remove_moderator(&id, &pubkey, now);
                let who = self.nick_for(&pubkey);
                self.publish_change(&id, result, ServerChange::ModeratorRemoved { who });
            }
            ServerCommand::Close | ServerCommand::Open => {
                let id = need_server!();
                let closing = matches!(command, ServerCommand::Close);
                let result = self.servers.set_closed(&id, closing, now);
                self.publish_change(&id, result, if closing { ServerChange::Closed } else { ServerChange::Opened });
            }
            ServerCommand::Policy { validity, renewal_window } => {
                let id = need_server!();
                let result = self.servers.set_cert_policy(&id, validity, renewal_window, now);
                self.publish_change(&id, result, ServerChange::Policy { validity_secs: validity, renewal_window_secs: renewal_window });
            }
            ServerCommand::Ban { target, duration, reason } => self.moderate(ModKind::Ban { until: duration.map(|d| now + d) }, &target, &reason),
            ServerCommand::Unban(target) => self.moderate(ModKind::Unban, &target, ""),
            ServerCommand::Allow(target) => self.moderate(ModKind::Admit, &target, ""),
            ServerCommand::Disallow(target) => self.moderate(ModKind::Unadmit, &target, ""),
        }
    }

    /// Ban, desban e allow-list. O dono grava direto na cadeia; um moderador publica uma ação
    /// assinada com o próprio certificado, que vale na hora e é consolidada pelo dono depois.
    fn moderate(&mut self, kind: ModKind, target: &str, reason: &str) {
        let Some(id) = self.active.server_id().map(str::to_string) else { return self.error(CoreError::InLobby) };
        let Some(pubkey) = self.resolve_pubkey(target) else { return self.error(CoreError::PeerNotFound(target.to_string())) };
        if pubkey == self.my_pubkey() {
            return self.error(CoreError::SelfModeration);
        }
        let now = super::now_secs();
        let owner = self.servers.get(&id).is_some_and(|s| s.is_owner());
        let who = self.nick_for(&pubkey);
        match self.servers.moderate(&id, &self.identity, kind.clone(), &pubkey, reason, now) {
            Ok(message) => {
                self.publish_server_message(&id, &message);
                self.notice(ServerNotice::Moderated { server: self.server_name(&id), target: who, kind, at: now, recorded_by_owner: owner });
            }
            Err(e) => self.error(CoreError::Server(e.to_string())),
        }
    }

    /// Mensagem do tópico de controle de um servidor
    pub(super) fn handle_server_network_message(&mut self, topic_server_id: &str, message: ServerMessage, from_pubkey: Option<&str>) {
        let now = super::now_secs();
        let me = self.my_pubkey();

        // Grupo cifrado (MLS): entrada, troca de chave e boas-vindas
        match &message {
            ServerMessage::KeyPackage { server_id, key_package } => {
                let Some(from) = from_pubkey else { return };
                match e2ee::admit_from_key_package(&mut self.mls, &self.servers, server_id, from, key_package, now) {
                    Ok(messages) => {
                        for m in &messages {
                            self.publish_server_message(server_id, m);
                        }
                        self.notice(ServerNotice::KeyGranted { to: self.nick_for(from) });
                    }
                    Err(E2eeError::NotOwner) => {}
                    Err(e) => tracing::debug!("Pedido de entrada no grupo recusado: {}", e),
                }
                return;
            }
            ServerMessage::Commit { server_id, commit } => {
                let owner = self.servers.get(server_id).map(|s| s.chain().state().owner.clone()).unwrap_or_default();
                match self.mls.process_commit(server_id, commit, &owner) {
                    Ok(CommitOutcome::Removed) => self.notice(ServerNotice::RemovedFromGroup { server: self.server_name(server_id) }),
                    // Perdemos algum Commit: descarta e pede entrada de novo. Um Commit de época futura
                    // não pode ser verificado, então só vale se quem publicou for o dono.
                    Ok(CommitOutcome::OutOfSync) if from_pubkey == Some(owner.as_str()) => self.mls.drop_group(server_id),
                    Ok(CommitOutcome::OutOfSync) => tracing::debug!("Commit fora de sincronia de quem não é o dono ignorado"),
                    Ok(_) => {}
                    Err(e) => tracing::debug!("Commit MLS inválido: {}", e),
                }
                return;
            }
            ServerMessage::Welcome { server_id, target, welcome } => {
                if *target == me && !self.mls.has_group(server_id) {
                    let owner = self.servers.get(server_id).map(|s| s.chain().state().owner.clone()).unwrap_or_default();
                    match self.mls.join(server_id, welcome, &owner) {
                        Ok(()) => self.notice(ServerNotice::KeyReceived { server: self.server_name(server_id) }),
                        Err(e) => tracing::debug!("Welcome MLS recusado: {}", e),
                    }
                }
                return;
            }
            _ => {}
        }
        let before = self.servers.get(topic_server_id).map(|s| (s.has_chain() && s.is_banned(&me, now), s.level_of(&me, now)));

        for event in self.servers.handle_message(message, from_pubkey, now) {
            match event {
                ServerEvent::ChainUpdated { server_id, name, height } => {
                    self.notice(ServerNotice::Synced { id: server_id.clone(), name, height });
                    if self.pending_switch.as_deref() == Some(server_id.as_str()) {
                        self.pending_switch = None;
                        self.enter_server(server_id);
                    } else if self.active.server_id() == Some(server_id.as_str()) {
                        self.refresh_space();
                    }
                }
                ServerEvent::Fork { server_id, height, replaced } => self.notice(ServerNotice::Fork { id: server_id, height, replaced }),
                ServerEvent::NeedBlocks { server_id, from_height } => {
                    self.publish_server_message(&server_id, &ServerMessage::ChainRequest { server_id: server_id.clone(), from_height });
                }
                ServerEvent::ActionAccepted { server_id, action } => self.notice(ServerNotice::ModerationReceived {
                    server: self.server_name(&server_id),
                    by: self.nick_for(action.actor()),
                    target: self.nick_for(&action.body.target),
                    kind: action.body.kind.clone(),
                    at: now,
                    reason: action.body.reason.clone(),
                }),
                ServerEvent::ActionsUndone { server_id, count } => {
                    self.notice(ServerNotice::ActionsUndone { server: self.server_name(&server_id), count })
                }
                ServerEvent::Reply { server_id, messages } => {
                    for m in &messages {
                        self.publish_server_message(&server_id, m);
                    }
                }
                ServerEvent::Ignored(reason) => tracing::debug!("Mensagem de servidor ignorada: {}", reason),
            }
        }

        // Mudanças que afetam este usuário
        let (Some((was_banned, was_level)), Some(server)) = (before, self.servers.get(topic_server_id)) else { return };
        let name = server.name();
        let banned = server.has_chain() && server.is_banned(&me, now);
        let level = server.level_of(&me, now);
        let owner = server.is_owner();
        if banned != was_banned {
            self.notice(ServerNotice::BanStatus { server: name.clone(), banned });
        }
        if level != was_level && !owner {
            self.notice(ServerNotice::Role { server: name, level });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_invite_roundtrip() {
        let id = "ab".repeat(32);
        assert_eq!(parse_invite(&invite_text("Rust Guild", &id)), Some(id.clone()));
        assert_eq!(parse_invite(&format!("entra aí: /server join {} valeu", id)), Some(id));
        assert_eq!(parse_invite("/server join abc"), None, "id curto não é convite");
        assert_eq!(parse_invite("bom dia"), None);
    }
}
