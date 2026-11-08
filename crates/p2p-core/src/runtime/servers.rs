//! Servidores: comandos, cadeia de configuração, moderação, passaportes, carimbos de tempo e o
//! grupo cifrado (MLS).

use super::{
    ChannelInfo, CoreError, CoreEvent, Role, Runtime, ServerChange, ServerCommand, ServerInfo, ServerListEntry, ServerNotice,
};
use crate::api::ChatMessage;
use crate::community::{
    self,
    e2ee::{self, CommitOutcome, E2eeError},
    server_control_topic, server_dht_key,
    timestamp::{self, TimestampAttestation},
    ChannelType, CommunityError, ModKind, PassportPermission, ServerEvent, ServerMessage, Space, TrustedTsa,
};
use base64::Engine as _;
use libp2p::gossipsub::IdentTopic;
use std::time::{Duration, Instant};

/// Intervalo entre pedidos de acesso de quem ainda não tem passaporte
const ACCESS_REQUEST_INTERVAL: Duration = Duration::from_secs(20);

/// Resultado de um pedido de carimbo a uma TSA, feito fora do loop de eventos
pub(super) struct StampResult {
    server_id: String,
    imprint: [u8; 32],
    tsa: String,
    result: Result<TimestampAttestation, String>,
}

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
        self.publish_gossip(topic, crate::wire::encode(message)).is_ok()
    }

    pub(super) fn default_channel(&self, server_id: &str) -> String {
        self.servers.get(server_id).and_then(|s| s.default_text_channel()).unwrap_or_else(|| "geral".to_string())
    }

    /// Participamos do servidor: cadeia sincronizada e passaporte válido (ou somos o dono)
    fn participating(&self, server_id: &str, now: u64) -> bool {
        let me = self.my_pubkey();
        self.servers.get(server_id).is_some_and(|s| s.has_chain() && s.is_allowed(&me, now))
    }

    fn enter_server(&mut self, server_id: String) {
        let now = super::now_secs();
        if self.participating(&server_id, now) && !self.mls.has_group(&server_id) {
            // Se já há outros membros online no tópico de controle do servidor, pedimos KeyPackage
            // para entrar no grupo deles; se não houver resposta até o próximo tick (ou estivermos sozinhos),
            // assumimos a liderança inicial criando o grupo.
            let ctrl_topic = IdentTopic::new(server_control_topic(&server_id));
            let has_peers_in_ctrl = !super::chat::channel_members_with_topics(
                &self.node.swarm.behaviour().gossipsub,
                &self.peer_metadata,
                &self.peer_topics,
                &ctrl_topic,
            )
            .is_empty();
            if has_peers_in_ctrl {
                self.request_group_key(&server_id);
            } else {
                let _ = self.mls.create_group(&server_id);
                self.announce_mls_group(&server_id);
            }
        } else if self.servers.get(&server_id).is_some_and(|s| s.has_chain()) && !self.participating(&server_id, now) {
            self.request_access(&server_id);
        }
        let channel = self.default_channel(&server_id);
        self.enter_channel(Space::Server(server_id), channel);
    }

    /// Publica o pacote de chave MLS com o nosso passaporte
    fn request_group_key(&mut self, server_id: &str) {
        if let Ok(key_package) = self.mls.key_package() {
            let passport = self.servers.get(server_id).and_then(|s| s.my_passport().cloned());
            if self.publish_server_message(server_id, &ServerMessage::KeyPackage { server_id: server_id.to_string(), key_package, passport }) {
                self.last_key_package.insert(server_id.to_string(), Instant::now());
            }
        }
    }

    /// Sem passaporte: pede um (servidor público responde automaticamente)
    fn request_access(&mut self, server_id: &str) {
        if self.last_access_request.get(server_id).is_some_and(|t| t.elapsed() < ACCESS_REQUEST_INTERVAL) {
            return;
        }
        if self.publish_server_message(server_id, &ServerMessage::AccessRequest { server_id: server_id.to_string() }) {
            self.last_access_request.insert(server_id.to_string(), Instant::now());
        }
    }

    /// Se somos o líder efetivo do grupo cifrado, remove agora quem está banido ou sem passaporte
    /// válido. Os membros validam esse Commit como qualquer outro.
    fn enforce_now(&mut self, server_id: &str) {
        let now = super::now_secs();
        if !self.mls.has_group(server_id) {
            return;
        }
        if let Ok(Some(commit)) = e2ee::enforce_membership(&mut self.mls, &self.servers, server_id, now) {
            self.publish_server_message(server_id, &commit);
            self.announce_mls_group(server_id);
        }
    }

    /// Pede carimbos de tempo para `imprint`: às TSAs da política (em threads, via HTTP) e às
    /// testemunhas da rede (pelo tópico de controle)
    fn request_stamps(&mut self, server_id: &str, imprint: [u8; 32]) {
        let nonce = timestamp::hex(&rand::random::<[u8; 8]>());
        self.publish_server_message(
            server_id,
            &ServerMessage::StampRequest { server_id: server_id.to_string(), imprint: timestamp::hex(&imprint), nonce },
        );
        let tsas = self.servers.get(server_id).map(|s| s.chain().state().timestamp_policy.tsas.clone()).unwrap_or_default();
        for tsa in tsas {
            let tx = self.stamp_tx.clone();
            let server_id = server_id.to_string();
            std::thread::spawn(move || {
                let result = timestamp::fetch_rfc3161(&tsa, &imprint).map_err(|e| e.to_string());
                let _ = tx.send(StampResult { server_id, imprint, tsa: tsa.name, result });
            });
        }
    }

    /// Carimbo de uma TSA chegou: anexa e repassa aos membros
    pub(super) fn on_stamp_result(&mut self, result: StampResult) {
        let StampResult { server_id, imprint, tsa, result } = result;
        match result {
            Ok(stamp) => {
                self.servers.attach_stamp(&server_id, &imprint, &stamp);
                self.publish_server_message(&server_id, &ServerMessage::Stamp { server_id: server_id.clone(), imprint: timestamp::hex(&imprint), stamp });
                self.notice(ServerNotice::StampObtained { server: self.server_name(&server_id), source: tsa });
            }
            Err(reason) => self.notice(ServerNotice::StampFailed { server: self.server_name(&server_id), tsa, reason }),
        }
    }

    /// Anuncia o grupo MLS atual (se formos o líder determinístico) para convergência
    pub(super) fn announce_mls_group(&mut self, server_id: &str) {
        if !self.mls.is_leader(server_id) {
            return;
        }
        let Some(epoch) = self.mls.epoch(server_id) else { return };
        let Some(leader) = self.mls.leader(server_id) else { return };
        let members: Vec<String> = self.mls.members(server_id).into_iter().collect();
        self.publish_server_message(
            server_id,
            &ServerMessage::GroupAnnounce {
                server_id: server_id.to_string(),
                epoch,
                leader,
                members,
            },
        );
    }

    /// Remove um par que desconectou do Swarm de todos os grupos MLS em que somos o líder atual
    pub(super) fn on_peer_disconnected_mls(&mut self, disconnected_pubkey: &str) {
        let ids: Vec<String> = self.servers.list().map(|s| s.server_id.clone()).collect();
        for id in ids {
            if self.mls.has_group(&id) && self.mls.members(&id).contains(disconnected_pubkey) {
                // Se quem saiu era o líder antigo e agora nós somos o menor restante,
                // ou se já éramos o líder: verificamos quem seria o líder sem o desconectado.
                let mut remaining = self.mls.members(&id);
                remaining.remove(disconnected_pubkey);
                if remaining.iter().min().map(String::as_str) == Some(self.my_pubkey().as_str()) {
                    // Força a remoção: se o desconectado tinha pubkey menor que a nossa,
                    // removemos diretamente a folha dele para assumir a liderança na nova época!
                    if let Ok(Some(commit)) = self.mls.remove_members_unchecked(&id, &[disconnected_pubkey.to_string()]) {
                        self.publish_server_message(&id, &ServerMessage::Commit { server_id: id.clone(), commit });
                        self.announce_mls_group(&id);
                    }
                }
            }
        }
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

    /// Ciclo periódico: pede cadeias que faltam, pede acesso, cuida do grupo
    /// cifrado e da manutenção do dono
    pub(super) fn server_sync_tick(&mut self) {
        for id in self.servers.list().filter(|s| !s.has_chain()).map(|s| s.server_id.clone()).collect::<Vec<_>>() {
            if let Some(request) = self.servers.chain_request(&id) {
                self.publish_server_message(&id, &request);
            }
        }
        let now = super::now_secs();
        let synced: Vec<String> = self.servers.list().filter(|s| s.has_chain()).map(|s| s.server_id.clone()).collect();
        for id in &synced {
            if !self.participating(id, now) {
                self.request_access(id);
            }
        }
        // Grupo cifrado efêmero com líder determinístico (menor pubkey):
        // O dono NÃO precisa estar online. Qualquer membro autorizado participa/lidera.
        let ids: Vec<String> = synced.into_iter().filter(|id| self.participating(id, now)).collect();
        for id in ids {
            if self.mls.has_group(&id) {
                if let Ok(Some(commit)) = e2ee::enforce_membership(&mut self.mls, &self.servers, &id, now) {
                    self.publish_server_message(&id, &commit);
                }
                if self.mls.is_leader(&id) {
                    if self.mls.needs_periodic_rotation(&id, e2ee::DEFAULT_KEY_ROTATION_INTERVAL) {
                        if let Ok(commit) = self.mls.rotate_key(&id) {
                            self.publish_server_message(&id, &ServerMessage::Commit { server_id: id.clone(), commit });
                        }
                    }
                    self.announce_mls_group(&id);
                }
            } else {
                // Ainda sem grupo MLS: se já pedimos KeyPackage há >= 5s e ninguém respondeu com Welcome,
                // criamos o grupo local (somos o primeiro membro online) e anunciamos.
                let waited_enough = self.last_key_package.get(&id).is_some_and(|t| t.elapsed() >= Duration::from_secs(5));
                if waited_enough {
                    let _ = self.mls.create_group(&id);
                    self.announce_mls_group(&id);
                } else if self.last_key_package.get(&id).is_none_or(|t| t.elapsed() >= Duration::from_secs(10)) {
                    if let Ok(key_package) = self.mls.key_package() {
                        let passport = self.servers.get(&id).and_then(|s| s.my_passport().cloned());
                        if self.publish_server_message(&id, &ServerMessage::KeyPackage { server_id: id.clone(), key_package, passport }) {
                            self.last_key_package.insert(id, Instant::now());
                        } else {
                            // Ninguém inscrito no tópico de controle: cria o grupo imediatamente!
                            let _ = self.mls.create_group(&id);
                        }
                    }
                }
            }
        }
        // Dono online: consolida ações de moderadores
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

    /// Emite um passaporte (pela chave do servidor ou pelo nosso passaporte), entrega ao titular e
    /// pede carimbo de tempo para ele
    fn issue_and_offer(&mut self, id: &str, target_pk: &str, permissions: Vec<PassportPermission>, duration: Option<u64>) -> Result<(), CommunityError> {
        let now = super::now_secs();
        let passport = self.servers.issue_passport(id, &self.identity, target_pk, permissions, duration, now)?;
        if let Some(server) = self.servers.get_mut(id) {
            server.learn_passport(&passport, now);
        }
        let _ = self.servers.persist(id);
        self.publish_server_message(id, &ServerMessage::PassportOffer { server_id: id.to_string(), target: target_pk.to_string(), passport: passport.clone() });
        self.request_stamps(id, passport.imprint());
        Ok(())
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
                        moderator: !s.is_owner() && s.has_chain() && s.is_moderator(&me, now),
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
                let role = if server.is_owner() || state.is_owner_key(&me) {
                    Role::Owner
                } else if server.is_moderator(&me, now) {
                    Role::Moderator
                } else {
                    Role::Member
                };
                let info = ServerInfo {
                    id: id.clone(),
                    name: server.name(),
                    safety_number: crate::identity::safety_number(&id),
                    mls_leader: self.mls.leader(&id).map(|pk| self.nick_for(&pk)),
                    mls_epoch: self.mls.epoch(&id),
                    height: head.map_or(0, |b| b.body.height),
                    updated_at: head.map(|b| b.body.timestamp),
                    channels: server.channels().into_iter().map(|c| ChannelInfo { voice: c.channel_type == ChannelType::Voice, name: c.name }).collect(),
                    role,
                    closed: state.closed,
                    passports_known: server.known_passports(),
                    moderators: server
                        .moderators(now)
                        .iter()
                        .map(|(pk, perms, until)| (self.nick_for(pk), perms.iter().map(|p| format!("{:?}", p)).collect(), *until))
                        .collect(),
                    bans: state.active_bans(now).iter().map(|(pk, ban)| (self.nick_for(pk), ban.until, self.nick_for(&ban.by))).collect(),
                    tsas: state.timestamp_policy.tsas.iter().map(|t| (t.name.clone(), t.url.clone())).collect(),
                    passport_validity_secs: state.passport_validity_secs,
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
                let sent = self.publish_gossip(lobby, crate::wire::encode(&invite)).is_ok();
                self.notice(if sent { ServerNotice::InviteSent { server: name } } else { ServerNotice::InviteManual { id: id.clone() } });
                if self.servers.get(&id).is_some_and(|s| s.chain().state().closed) {
                    self.notice(ServerNotice::InviteNeedsPassport);
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
            ServerCommand::AddModerator { target } => {
                let id = need_server!();
                let pubkey = need_peer!(target);
                let validity_secs = self.servers.get(&id).map_or(0, |s| s.chain().state().passport_validity_secs);
                let who = self.nick_for(&pubkey);
                match self.issue_and_offer(&id, &pubkey, PassportPermission::default_moderator(), None) {
                    Ok(()) => self.notice(ServerNotice::Changed { server: self.server_name(&id), change: ServerChange::ModeratorAdded { who, validity_secs } }),
                    Err(e) => self.error(CoreError::Server(e.to_string())),
                }
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
                let result = self.servers.set_passport_policy(&id, validity, renewal_window, now);
                self.publish_change(&id, result, ServerChange::Policy { validity_secs: validity, renewal_window_secs: renewal_window });
            }
            ServerCommand::AddTsa { name, url, public_key_b64 } => {
                let id = need_server!();
                let Ok(spki_der) = base64::engine::general_purpose::STANDARD.decode(public_key_b64.trim()) else {
                    return self.error(CoreError::Server("Chave pública da TSA deve estar em base64 (SubjectPublicKeyInfo DER)".into()));
                };
                let result = self.servers.add_tsa(&id, TrustedTsa { name: name.clone(), url, spki_der }, now);
                self.publish_change(&id, result, ServerChange::TsaAdded(name));
            }
            ServerCommand::RemoveTsa(name) => {
                let id = need_server!();
                let result = self.servers.remove_tsa(&id, &name, now);
                self.publish_change(&id, result, ServerChange::TsaRemoved(name));
            }
            ServerCommand::Ban { target, duration, reason } => self.moderate(ModKind::Ban { until: duration.map(|d| now + d) }, &target, &reason),
            ServerCommand::Unban(target) => self.moderate(ModKind::Unban, &target, ""),
            ServerCommand::Revoke(target) => {
                let id = need_server!();
                let pubkey = need_peer!(target);
                let Some(serial) = self.servers.get(&id).and_then(|s| s.passport_of(&pubkey)).map(|p| p.body.serial.clone()) else {
                    return self.error(CoreError::Server("Nenhum passaporte conhecido desse participante".into()));
                };
                self.moderate(ModKind::Revoke { serial }, &pubkey, "");
            }
            ServerCommand::RotateKey => {
                let id = need_server!();
                match self.mls.rotate_key(&id) {
                    Ok(commit) => {
                        self.publish_server_message(&id, &ServerMessage::Commit { server_id: id.clone(), commit });
                        self.announce_mls_group(&id);
                        let epoch = self.mls.epoch(&id).unwrap_or(0);
                        self.notice(ServerNotice::KeyRotated { server: self.server_name(&id), epoch });
                    }
                    Err(e) => self.error(CoreError::Server(e.to_string())),
                }
            }
            ServerCommand::IssuePassport { target, moderator, duration } => {
                let id = need_server!();
                let target_pk = need_peer!(target);
                let perms = if moderator { PassportPermission::default_moderator() } else { PassportPermission::member() };
                match self.issue_and_offer(&id, &target_pk, perms, duration) {
                    Ok(()) => self.notice(ServerNotice::PassportUpdated { server: self.server_name(&id) }),
                    Err(e) => self.error(CoreError::Server(e.to_string())),
                }
            }
            ServerCommand::ShowPassport => {
                let id = need_server!();
                let Some(server) = self.servers.get(&id) else { return };
                if let Some(p) = server.my_passport() {
                    let perms = p.body.permissions.iter().map(|p| format!("{:?}", p)).collect();
                    self.notice(ServerNotice::PassportInfo {
                        server: self.server_name(&id),
                        holder: p.body.holder.clone(),
                        issuer: p.body.issuer.clone(),
                        chain_depth: p.chain_depth(),
                        stamps: p.stamps.len(),
                        expires_at: p.effective_expires_at(),
                        permissions: perms,
                    });
                } else {
                    self.error(CoreError::Server("Você ainda não possui um passaporte registrado neste servidor".into()));
                }
            }
            ServerCommand::FlattenPassport => {
                let id = need_server!();
                let Some(server) = self.servers.get(&id) else { return };
                if let Some(p) = server.my_passport().cloned() {
                    if p.chain_depth() > 1 {
                        self.publish_server_message(&id, &ServerMessage::FlattenRequest { server_id: id.clone(), passport: p });
                    }
                    self.notice(ServerNotice::PassportUpdated { server: self.server_name(&id) });
                } else {
                    self.error(CoreError::Server("Você não possui passaporte neste servidor".into()));
                }
            }
        }
    }

    /// Ban, desban e revogação. O dono grava direto na cadeia; um moderador publica uma ação
    /// assinada com o próprio passaporte, que vale na hora, recebe carimbos de tempo e é
    /// consolidada pelo dono depois.
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
                if let ServerMessage::Action(action) = &message {
                    self.request_stamps(&id, action.imprint());
                }
                self.enforce_now(&id);
                self.publish_channel_members();
                self.notice(ServerNotice::Moderated { server: self.server_name(&id), target: who, kind, at: now, recorded_by_owner: owner });
            }
            Err(e) => self.error(CoreError::Server(e.to_string())),
        }
    }

    /// Mensagem do tópico de controle de um servidor
    pub(super) fn handle_server_network_message(&mut self, topic_server_id: &str, message: ServerMessage, from_pubkey: Option<&str>) {
        let now = super::now_secs();
        let me = self.my_pubkey();

        // Grupo cifrado (MLS), passaportes e carimbos
        match &message {
            ServerMessage::KeyPackage { server_id, key_package, passport } => {
                let Some(from) = from_pubkey else { return };
                if let (Some(p), Some(server)) = (passport, self.servers.get_mut(server_id)) {
                    if p.body.holder == from && server.learn_passport(p, now) {
                        let _ = self.servers.persist(server_id);
                    }
                }

                match e2ee::admit_from_key_package(&mut self.mls, &self.servers, server_id, from, key_package, passport.as_ref(), now) {
                    Ok(messages) => {
                        for m in &messages {
                            self.publish_server_message(server_id, m);
                        }
                        self.announce_mls_group(server_id);
                        self.notice(ServerNotice::KeyGranted { to: self.nick_for(from) });
                    }
                    Err(E2eeError::NotOwner | E2eeError::NotInGroup) => {}
                    Err(e) => tracing::debug!("Pedido de entrada no grupo recusado: {}", e),
                }
                return;
            }
            ServerMessage::AccessRequest { server_id } => {
                let Some(from) = from_pubkey else { return };
                if from == me {
                    return;
                }
                let closed = self.servers.get(server_id).is_some_and(|s| s.has_chain() && s.chain().state().closed);
                if let Some(offer) = self.servers.answer_access_request(server_id, &self.identity, from, now) {
                    if let ServerMessage::PassportOffer { passport, .. } = &offer {
                        let imprint = passport.imprint();
                        if let Some(server) = self.servers.get_mut(server_id) {
                            server.learn_passport(passport, now);
                        }
                        self.publish_server_message(server_id, &offer);
                        self.request_stamps(server_id, imprint);
                    }
                } else if closed && self.servers.get(server_id).is_some_and(|s| s.is_moderator(&me, now)) {
                    self.notice(ServerNotice::AccessRequested { server: self.server_name(server_id), who: self.nick_for(from) });
                }
                return;
            }
            ServerMessage::StampRequest { server_id, imprint, nonce } => {
                if from_pubkey == Some(me.as_str()) {
                    return;
                }
                if let Some(stamp) = self.servers.witness_stamp(server_id, &self.identity, imprint, nonce, now) {
                    self.publish_server_message(server_id, &stamp);
                }
                return;
            }
            ServerMessage::Commit { server_id, commit } => {
                let Some(server) = self.servers.get(server_id).filter(|s| s.has_chain()) else { return };
                let owner = server.chain().state().owner.clone();
                let current_leader = self.mls.leader(server_id);
                let outcome = self.mls.process_commit_with_validator(server_id, commit, &owner, |pk| !server.is_excluded(pk, now), |pk| server.is_allowed(pk, now));
                match outcome {
                    Ok(CommitOutcome::Applied { epoch }) => {
                        if let Some(from) = from_pubkey {
                            if current_leader.as_deref() == Some(from) && from != me {
                                let name = self.server_name(server_id);
                                self.notice(ServerNotice::KeyRotated { server: name, epoch });
                            }
                        }
                    }
                    Ok(CommitOutcome::Removed) => self.notice(ServerNotice::RemovedFromGroup { server: self.server_name(server_id) }),
                    // Perdemos algum Commit: descarta e pede entrada de novo se veio de um membro válido
                    Ok(CommitOutcome::OutOfSync)
                        if from_pubkey.is_some_and(|pk| !server.is_excluded(pk, now) && (current_leader.as_deref() == Some(pk) || pk == owner)) =>
                    {
                        self.mls.drop_group(server_id);
                        self.request_group_key(server_id);
                    }
                    Ok(CommitOutcome::OutOfSync) => tracing::debug!("Commit fora de sincronia de não-líder ignorado"),
                    Ok(_) => {}
                    Err(e) => tracing::debug!("Commit MLS inválido: {}", e),
                }
                return;
            }
            ServerMessage::Welcome { server_id, target, welcome, member_passports } => {
                if *target == me {
                    // Passaportes dos membros: com eles validamos o grupo e os Commits seguintes do líder
                    if let Some(server) = self.servers.get_mut(server_id) {
                        for p in member_passports {
                            server.learn_passport(p, now);
                        }
                    }
                    let _ = self.servers.persist(server_id);
                    let Some(server) = self.servers.get(server_id).filter(|s| s.has_chain()) else { return };
                    let had_group = self.mls.has_group(server_id);
                    let res = self.mls.join_with_validator(server_id, welcome, |sender_pk, members| {
                        server.is_allowed(sender_pk, now) && members.iter().all(|pk| server.is_allowed(pk, now))
                    });
                    match res {
                        Ok(()) => {
                            if !had_group {
                                self.notice(ServerNotice::KeyReceived { server: self.server_name(server_id) });
                            }
                            let needs_flatten = self.servers.get(server_id).and_then(|s| s.my_passport()).map(|p| (p.chain_depth() > 1, p.clone()));
                            if let Some((true, my_p)) = needs_flatten {
                                self.publish_server_message(server_id, &ServerMessage::FlattenRequest { server_id: server_id.clone(), passport: my_p });
                            }
                        }
                        Err(e) => tracing::debug!("Welcome MLS recusado: {}", e),
                    }
                }
                return;
            }
            ServerMessage::PassportOffer { server_id, target, passport } => {
                if *target == me {
                    let was_moderator = self.servers.get(server_id).is_some_and(|s| s.has_chain() && s.is_moderator(&me, now));
                    if self.servers.accept_my_passport(server_id, &me, passport, now) {
                        self.notice(ServerNotice::PassportUpdated { server: self.server_name(server_id) });
                        let server = self.servers.get(server_id);
                        let moderator = server.is_some_and(|s| s.has_chain() && s.is_moderator(&me, now));
                        if moderator != was_moderator && !server.is_some_and(|s| s.is_owner()) {
                            self.notice(ServerNotice::Role { server: self.server_name(server_id), moderator });
                        }
                        if let Some(request) = self.servers.chain_request(server_id).filter(|_| !self.servers.get(server_id).is_some_and(|s| s.has_chain())) {
                            self.publish_server_message(server_id, &request);
                        }
                        if self.active.server_id() == Some(server_id.as_str()) {
                            self.enter_server(server_id.clone());
                        }
                    }
                } else if let Some(server) = self.servers.get_mut(server_id) {
                    if server.learn_passport(passport, now) {
                        let _ = self.servers.persist(server_id);
                    }
                }
                return;
            }
            ServerMessage::FlattenRequest { server_id, passport } => {
                if let Some(server) = self.servers.get(server_id) {
                    let flattened = if let Some(owner_key) = server.owner_key() {
                        passport.flatten_with_server_key(owner_key, now).ok()
                    } else if let Some(my_p) = server.my_passport() {
                        let can_issue = my_p.allows(PassportPermission::IssueMember) || my_p.allows(PassportPermission::Delegate);
                        can_issue.then(|| passport.flatten_with_superior(&self.identity, my_p, now).ok()).flatten()
                    } else {
                        None
                    };
                    if let Some(flattened) = flattened.filter(|p| server.effective_state(now).verify_passport(p, now).is_ok()) {
                        let imprint = flattened.imprint();
                        self.publish_server_message(server_id, &ServerMessage::PassportOffer {
                            server_id: server_id.clone(),
                            target: passport.body.holder.clone(),
                            passport: flattened,
                        });
                        self.request_stamps(server_id, imprint);
                    }
                }
                return;
            }
            ServerMessage::GroupAnnounce { server_id, leader, members, .. } => {
                let Some(from) = from_pubkey else { return };
                let Some(server) = self.servers.get(server_id).filter(|s| s.has_chain()) else { return };
                if from != leader || !server.is_allowed(&me, now) || server.is_excluded(from, now) {
                    return;
                }
                let candidate_set: std::collections::BTreeSet<String> =
                    members.iter().filter(|pk| !server.is_excluded(pk, now)).cloned().collect();
                if candidate_set.iter().min().map(String::as_str) != Some(leader.as_str()) {
                    return;
                }
                let current_set = self.mls.members(server_id);
                // Se não estamos no grupo anunciado (ou se nosso grupo local perder na convergência),
                // enviamos KeyPackage para convergir para o grupo vencedor!
                if !current_set.contains(&me) || (!candidate_set.contains(&me) && e2ee::should_adopt_group(&current_set, &candidate_set)) {
                    // O OpenMLS não aceita o Welcome com outro grupo de mesmo id guardado: o grupo
                    // local (que perdeu a convergência) sai antes de pedirmos a entrada no vencedor
                    self.mls.drop_group(server_id);
                    self.request_group_key(server_id);
                }
                return;
            }
            _ => {}
        }
        let before = self.servers.get(topic_server_id).map(|s| (s.has_chain() && s.is_banned(&me, now), s.has_chain() && s.is_moderator(&me, now)));

        let mut governance_changed = false;
        for event in self.servers.handle_message(message, from_pubkey, now) {
            governance_changed |= matches!(
                event,
                ServerEvent::ChainUpdated { .. } | ServerEvent::ActionAccepted { .. } | ServerEvent::ActionsUndone { .. } | ServerEvent::StampAttached { .. }
            );
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
                    let passport = self.servers.get(&server_id).and_then(|s| s.my_passport().cloned());
                    self.publish_server_message(&server_id, &ServerMessage::ChainRequest { server_id: server_id.clone(), from_height, passport });
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
                ServerEvent::StampAttached { server_id } => tracing::debug!("Carimbo de tempo anexado em {}", community::short_id(&server_id)),
                ServerEvent::Ignored(reason) => tracing::debug!("Mensagem de servidor ignorada: {}", reason),
            }
        }

        // Ban, revogação ou ação nova: o líder tira do grupo cifrado na hora quem perdeu o direito
        if governance_changed {
            self.enforce_now(topic_server_id);
            if self.active.server_id() == Some(topic_server_id) {
                self.publish_channel_members();
            }
        }

        // Mudanças que afetam este usuário
        let (Some((was_banned, was_moderator)), Some(server)) = (before, self.servers.get(topic_server_id)) else { return };
        let name = server.name();
        let banned = server.has_chain() && server.is_banned(&me, now);
        let moderator = server.has_chain() && server.is_moderator(&me, now);
        let owner = server.is_owner();
        if banned != was_banned {
            self.notice(ServerNotice::BanStatus { server: name.clone(), banned });
        }
        if moderator != was_moderator && !owner {
            self.notice(ServerNotice::Role { server: name, moderator });
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
