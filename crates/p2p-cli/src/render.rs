//! Texto em português dos eventos do core. O core só manda eventos tipados; a escolha das
//! palavras (e dos emojis) é da interface.

use p2p_core::community::{format_duration, short_id, ModKind};
use p2p_core::files::{FileEvent, FileState, FileSummary};
use p2p_core::runtime::{
    CoreError, CoreEvent, NetworkEvent, Role, ScreenEvent, ServerChange, ServerInfo, ServerNotice, SpaceInfo, VoiceEvent,
};

/// Ajuda dos comandos de servidor
pub const SERVER_HELP: &str = "Comandos: /server create <nome> | join <id> | accept | list | switch <nome|id|lobby> | info | history \
| invite | channel add <nome> [voz] | channel remove <nome> | mod add <par> [nível] | mod remove <par> \
| ban <par> [30m|12h|3d|2w|perm] [motivo] | unban <par> | allow <par> | disallow <par> | close | open \
| policy <validade> <janela> (ex.: 7d 2d) | leave  (atalho: /lobby)";

pub fn space_label(space: &SpaceInfo) -> String {
    match space {
        SpaceInfo::Lobby => "🌐 Lobby".to_string(),
        SpaceInfo::Server { name: Some(name), .. } => format!("🏰 {}", name),
        SpaceInfo::Server { id, name: None } => format!("🏰 {}", short_id(id)),
    }
}

pub fn human_size(bytes: u64) -> String {
    match bytes {
        b if b >= 1 << 30 => format!("{:.1} GB", b as f64 / (1u64 << 30) as f64),
        b if b >= 1 << 20 => format!("{:.1} MB", b as f64 / (1u64 << 20) as f64),
        b if b >= 1 << 10 => format!("{:.0} KB", b as f64 / 1024.0),
        b => format!("{} B", b),
    }
}

/// Data UTC legível ("2026-11-02 18:20 UTC"), sem depender de biblioteca de datas
pub fn fmt_utc(secs: u64) -> String {
    // Algoritmo de datas civis de Howard Hinnant (dias desde 1970-01-01 -> ano/mês/dia)
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", year, month, day, rem / 3600, rem % 3600 / 60)
}

/// Linhas de texto para a aba Sistema (ou para o terminal do daemon). Eventos que a interface
/// mostra de outro jeito (mensagens de chat, listas de membros, progresso) não geram texto.
pub fn describe(event: &CoreEvent) -> Vec<String> {
    let one = |s: String| vec![s];
    match event {
        CoreEvent::Started { .. } => Vec::new(),
        CoreEvent::Network(e) => one(network(e)),
        CoreEvent::PeerIdentified { .. } | CoreEvent::PeerLeft { .. } => Vec::new(),
        CoreEvent::Peers { anarchord, connections } => {
            one(format!("Pares Anarchord conectados: {} (conexões totais, incluindo DHT: {})", anarchord, connections))
        }
        CoreEvent::AudioDevices { inputs, outputs } => {
            vec![format!("🎤 Entradas: {}", inputs.join(" | ")), format!("🔊 Saídas: {}", outputs.join(" | "))]
        }
        CoreEvent::SpaceChanged { .. } | CoreEvent::ServersChanged(_) | CoreEvent::ChannelMembers { .. } => Vec::new(),
        CoreEvent::ChannelEntered { space, channel } => one(format!("🚀 {} #{}", space_label(space), channel)),
        CoreEvent::ChatMessage { .. } => Vec::new(),
        CoreEvent::InviteReceived { from, known: false, .. } => one(format!("💡 Convite de {}: digite /server accept para entrar", from)),
        CoreEvent::InviteReceived { .. } => Vec::new(),
        CoreEvent::Voice(e) => voice(e).into_iter().collect(),
        CoreEvent::Screen(e) => screen(e),
        CoreEvent::File(e) => file(e).into_iter().collect(),
        CoreEvent::Files(list) => files(list),
        CoreEvent::FilePreparing { name } => one(format!("📁 Preparando '{}' para compartilhar...", name)),
        CoreEvent::Server(notice) => server(notice),
        CoreEvent::Error(e) => one(error(e)),
        CoreEvent::Stopped => one("👋 Anarchord encerrado.".to_string()),
    }
}

fn network(event: &NetworkEvent) -> String {
    match event {
        NetworkEvent::Listening(addr) => format!("Endereço de escuta: {}", addr),
        NetworkEvent::ExternalAddress(addr) => format!("🌐 Endereço externo confirmado: {}", addr),
        NetworkEvent::DhtBootstrap { nodes } => format!("🌍 DHT Amino: {} nós de bootstrap registrados", nodes),
        NetworkEvent::Dialing(addr) => format!("⏳ Conectando ao par remoto: {}", addr),
        NetworkEvent::TrackerPeer(addr) => format!("📡 Par descoberto via BitTorrent Tracker: {}", addr),
        NetworkEvent::BehindNat => "🧱 AutoNAT: nó atrás de NAT. Buscando relays públicos...".to_string(),
        NetworkEvent::RelayRequested { relay, .. } => format!("🛰️ Pedindo reserva no relay {}", relay),
        NetworkEvent::RelayReserved(relay) => format!("🛰️ Reserva aceita no relay {}", relay),
        NetworkEvent::HolePunched(peer) => format!("🕳️ Hole punching OK: conexão direta com {}", peer),
        NetworkEvent::ConnectionClosed { peer_id, cause } => format!("👋 Conexão fechada com {} ({})", peer_id, cause),
        NetworkEvent::AudioUnavailable(reason) => format!("⚠️ Áudio nativo indisponível: {}", reason),
    }
}

fn voice(event: &VoiceEvent) -> Option<String> {
    Some(match event {
        VoiceEvent::Joined(room) => format!("🔊 Conectado à sala de voz [🔊 {}]", room),
        VoiceEvent::Left(room) => format!("🔇 Saiu da sala de voz [{}].", room),
        VoiceEvent::Members(_) => return None,
        VoiceEvent::Speaking { nick, speaking: true } => format!("🔊 [VOZ] {} começou a falar...", nick),
        VoiceEvent::Speaking { nick, speaking: false } => format!("🔇 [VOZ] {} parou de falar.", nick),
        VoiceEvent::Muted(true) => "Microfone MUTADO.".to_string(),
        VoiceEvent::Muted(false) => "Microfone ATIVADO.".to_string(),
        VoiceEvent::AudioReady => "🎤 Subsistema de áudio ativado.".to_string(),
        VoiceEvent::SynthStarted => "📻 Sintetizador 8-bits tocando na sala de voz (Opus).".to_string(),
    })
}

fn screen(event: &ScreenEvent) -> Vec<String> {
    vec![match event {
        ScreenEvent::Monitors(screens) => {
            let list: Vec<String> = screens
                .iter()
                .enumerate()
                .map(|(i, s)| format!("[{}] {} ({}x{}){}", i, s.name, s.width, s.height, if s.is_primary { " (Primária)" } else { "" }))
                .collect();
            format!("Telas locais detectadas ({}): {}", screens.len(), list.join(" | "))
        }
        ScreenEvent::ShareStarted { stream_id, synthetic: true, .. } => {
            format!("📺 [VÍDEO H.264] Transmissão animada iniciada a 30 FPS (Stream ID: {})", stream_id)
        }
        ScreenEvent::ShareStarted { stream_id, quality, .. } => {
            format!("📺 Transmissão H.264 (30 FPS, {}p) INICIADA (Stream ID: {}). Use /screen stop para encerrar.", quality, stream_id)
        }
        ScreenEvent::ShareStopped => "📺 Transmissão de tela ENCERRADA.".to_string(),
        ScreenEvent::FrameSent { seq, bytes } => format!("📺 [VÍDEO ENVIADO] Quadro #{} transmitido na malha ({:.1} KB)", seq, *bytes as f32 / 1024.0),
        ScreenEvent::StreamAvailable { nick, .. } => format!("📺 Nova tela compartilhada por '{}'. Digite /screen watch {}", nick, nick),
        ScreenEvent::FrameReceived { nick, seq, bytes, width, height } => format!(
            "📺 [DAEMON VÍDEO] Recebendo transmissão de '{}': quadro #{} ({:.1} KB, {}x{})",
            nick,
            seq,
            *bytes as f32 / 1024.0,
            width,
            height
        ),
        ScreenEvent::Watching { nick, .. } => format!("📺 Assistindo transmissão de '{}'. Pressione ESC na janela para fechar.", nick),
        ScreenEvent::WatchEnded => "📺 Janela de vídeo fechada.".to_string(),
    }]
}

fn file(event: &FileEvent) -> Option<String> {
    Some(match event {
        FileEvent::Offered { cid, name, size, from, direct } => format!(
            "📎 {} {} '{}' ({}). Baixe com /get {}",
            from,
            if *direct { "te enviou" } else { "compartilhou" },
            name,
            human_size(*size),
            cid.short()
        ),
        FileEvent::Shared { cid, name } => format!("📤 '{}' compartilhado (id {}). Fica disponível enquanto o app estiver aberto.", name, cid.short()),
        FileEvent::Started { name, .. } => format!("📥 Baixando '{}'...", name),
        FileEvent::Progress { .. } => return None,
        FileEvent::Completed { name, path, .. } => {
            format!("💾 '{}' salvo em {}. Agora você também compartilha com quem pedir.", name, path.display())
        }
        FileEvent::Failed { name, reason, .. } => format!("❌ '{}': {}", name, reason),
        FileEvent::Dismissed { name } => format!("Oferta de '{}' recusada.", name),
        FileEvent::Unshared { name } => format!("📁 '{}' não está mais sendo compartilhado nem baixado.", name),
    })
}

fn files(list: &[FileSummary]) -> Vec<String> {
    if list.is_empty() {
        return vec!["📁 Nenhum arquivo. Compartilhe com /share <arquivo>.".to_string()];
    }
    list.iter()
        .map(|file| {
            let state = match &file.state {
                FileState::Offered => format!("oferecido por {} · /get {}", file.from, file.cid.short()),
                FileState::Downloading { progress, peers } => format!("baixando {:.0}% de {} par(es)", progress * 100.0, peers),
                FileState::Seeding => "compartilhando".to_string(),
            };
            format!("📁 [{}] {} ({}) — {}", file.cid.short(), file.name, human_size(file.size), state)
        })
        .collect()
}

fn moderation_text(target: &str, kind: &ModKind, at: u64) -> String {
    match kind {
        ModKind::Ban { until } => format!("baniu {} ({})", target, format_duration(until.map(|u| u.saturating_sub(at)))),
        ModKind::Unban => format!("desbaniu {}", target),
        ModKind::Admit => format!("admitiu {}", target),
        ModKind::Unadmit => format!("removeu {} da allow-list", target),
    }
}

fn server(notice: &ServerNotice) -> Vec<String> {
    let one = |s: String| vec![s];
    match notice {
        ServerNotice::Created { id, name } => one(format!(
            "🏰 Servidor '{}' criado (id {}). Você é o dono (nível 0). Chat, voz e tela do servidor são cifrados de ponta a ponta. \
             Use /server invite para convidar.",
            name,
            short_id(id)
        )),
        ServerNotice::Searching { id } => one(format!(
            "⏳ Procurando membros online do servidor {}... você entra assim que a configuração chegar \
             (servidor fechado: é preciso estar na allow-list).",
            short_id(id)
        )),
        ServerNotice::WaitingConfig { id } => one(format!("⏳ A configuração de {} ainda não chegou; você entra assim que chegar.", short_id(id))),
        ServerNotice::Left { name, was_owner } => one(format!(
            "👋 Você saiu do servidor '{}'.{}",
            name,
            if *was_owner { " A chave de dono continua salva em disco." } else { "" }
        )),
        ServerNotice::Synced { name, height, .. } => one(format!("📜 '{}' sincronizado (bloco {}).", name, height)),
        ServerNotice::Fork { id, height, replaced } => one(format!(
            "⚠️ Fork na cadeia de {} no bloco {} (a chave do dono foi usada em dois lugares?): {}.",
            short_id(id),
            height,
            if *replaced { "adotado o ramo vencedor" } else { "mantido o ramo atual" }
        )),
        ServerNotice::Changed { change, .. } => one(match change {
            ServerChange::ChannelAdded { name, voice } => format!("✅ Canal {}{} criado.", if *voice { "🔊 " } else { "#" }, name),
            ServerChange::ChannelRemoved(name) => format!("🗑️ Canal {} removido.", name),
            ServerChange::ModeratorAdded { who, level, validity_secs } => format!(
                "🛡️ {} agora é moderador nível {} (certificado de {}, renovado automaticamente).",
                who,
                level,
                format_duration(Some(*validity_secs))
            ),
            ServerChange::ModeratorRemoved { who } => {
                format!("🛡️ Certificado de {} revogado. Ações dele ainda não consolidadas serão desfeitas.", who)
            }
            ServerChange::Closed => {
                "🔒 Servidor fechado: só dono, moderadores e quem está na allow-list participam. Admita com /server allow <par>.".to_string()
            }
            ServerChange::Opened => "🔓 Servidor aberto: qualquer um com o id pode entrar.".to_string(),
            ServerChange::Policy { validity_secs, renewal_window_secs } => format!(
                "⏳ Certificados: validade {}, renovação nos últimos {}.",
                format_duration(Some(*validity_secs)),
                format_duration(Some(*renewal_window_secs))
            ),
        }),
        ServerNotice::Moderated { target, kind, at, recorded_by_owner, .. } => {
            let what = match kind {
                ModKind::Ban { until } => format!("🔨 {} foi banido ({}).", target, format_duration(until.map(|u| u.saturating_sub(*at)))),
                ModKind::Unban => format!("🕊️ {} foi desbanido.", target),
                ModKind::Admit => format!("✅ {} entrou na allow-list.", target),
                ModKind::Unadmit => format!("🚫 {} saiu da allow-list.", target),
            };
            let note = if *recorded_by_owner { " Gravado na cadeia." } else { " Vale agora; fica definitivo quando o dono consolidar." };
            one(format!("{}{}", what, note))
        }
        ServerNotice::ModerationReceived { server, by, target, kind, at, reason } => {
            let reason = if reason.is_empty() { String::new() } else { format!(" — motivo: {}", reason) };
            one(format!("🔨 [{}] {} {}{}", server, by, moderation_text(target, kind, *at), reason))
        }
        ServerNotice::ActionsUndone { server, count } => one(format!(
            "↩️ [{}] {} ação(ões) de moderação desfeita(s): o certificado do moderador foi revogado ou expirou.",
            server, count
        )),
        ServerNotice::BanStatus { server, banned: true } => {
            one(format!("⛔ Você foi banido de '{}': suas mensagens serão ignoradas pelos membros.", server))
        }
        ServerNotice::BanStatus { server, banned: false } => one(format!("🕊️ Seu ban em '{}' acabou.", server)),
        ServerNotice::Role { server, level: Some(level) } => one(format!("🛡️ Você agora é moderador nível {} em '{}'.", level, server)),
        ServerNotice::Role { server, level: None } => one(format!("🛡️ Você não é mais moderador em '{}'.", server)),
        ServerNotice::KeyGranted { to } => one(format!("🔐 {} recebeu a chave do grupo cifrado.", to)),
        ServerNotice::KeyReceived { server } => {
            one(format!("🔐 Chave do grupo de '{}' recebida: chat, voz e tela cifrados de ponta a ponta.", server))
        }
        ServerNotice::RemovedFromGroup { server } => {
            one(format!("🔐 Você foi removido do grupo cifrado de '{}': não recebe mais o conteúdo do servidor.", server))
        }
        ServerNotice::InviteSent { server } => {
            one(format!("📨 Convite para '{}' publicado no 🌐 Lobby #geral. Quem estiver lá digita /server accept.", server))
        }
        ServerNotice::InviteManual { id } => one(format!("⚠️ Ninguém no 🌐 Lobby #geral agora. Id do servidor para convite manual: {}", id)),
        ServerNotice::InviteNeedsAllow => {
            one("🔒 Servidor fechado: admita a pessoa com /server allow <par> para ela conseguir entrar.".to_string())
        }
        ServerNotice::List { lobby_current, servers } => {
            let marker = |on: bool| if on { "▶" } else { " " };
            let mut lines = vec![format!("{} 🌐 Lobby  (/server switch lobby)", marker(*lobby_current))];
            if servers.is_empty() {
                lines.push("  Nenhum servidor. Crie com /server create <nome> ou aceite um convite.".to_string());
            }
            for s in servers {
                let mut tags = Vec::new();
                if s.owner {
                    tags.push("dono".to_string());
                } else if let Some(level) = s.moderator_level {
                    tags.push(format!("moderador n{}", level));
                }
                if s.pending {
                    tags.push("aguardando configuração".into());
                }
                if s.closed {
                    tags.push("fechado".into());
                }
                if s.banned {
                    tags.push("banido".into());
                }
                let tags = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };
                lines.push(format!("{} 🏰 {} ({}){}", marker(s.current), s.name, short_id(&s.id), tags));
            }
            lines
        }
        ServerNotice::Info(info) => server_info(info),
        ServerNotice::History(history) => {
            let mut lines = vec![format!("📜 Histórico de alterações ({} blocos, mais recentes por último):", history.len())];
            for entry in history.iter().skip(history.len().saturating_sub(15)) {
                lines.push(format!("   #{} {} — {}", entry.height, fmt_utc(entry.timestamp), entry.description));
            }
            lines
        }
        ServerNotice::Help => one(SERVER_HELP.to_string()),
    }
}

fn server_info(info: &ServerInfo) -> Vec<String> {
    let channels: Vec<String> = info.channels.iter().map(|c| format!("{}{}", if c.voice { "🔊 " } else { "#" }, c.name)).collect();
    let role = match info.role {
        Role::Owner => "dono (nível 0)".to_string(),
        Role::Moderator(level) => format!("moderador nível {}", level),
        Role::Member => "membro".to_string(),
    };
    let access = if info.closed { format!("fechado, {} na allow-list", info.allow_list) } else { "aberto".to_string() };
    let mods: Vec<String> = info.moderators.iter().map(|(nick, level, until)| format!("{} (n{}, até {})", nick, level, fmt_utc(*until))).collect();
    let bans: Vec<String> = info
        .bans
        .iter()
        .map(|(nick, until, by)| {
            let until = until.map_or("permanente".to_string(), |u| format!("até {}", fmt_utc(u)));
            format!("{} ({}, por n{})", nick, until, by)
        })
        .collect();
    let none_or = |list: Vec<String>| if list.is_empty() { "nenhum".to_string() } else { list.join(", ") };
    vec![
        format!("🏰 {} | bloco {} ({}) | id {}", info.name, info.height, info.updated_at.map(fmt_utc).unwrap_or_default(), info.id),
        format!("   Canais: {}", channels.join(", ")),
        format!("   Você: {} | Acesso: {}", role, access),
        format!("   Moderadores: {}", none_or(mods)),
        format!("   Banidos: {}", none_or(bans)),
        format!(
            "   Certificados: validade {}, renovação nos últimos {} | Ações aguardando o dono: {}",
            format_duration(Some(info.cert_validity_secs)),
            format_duration(Some(info.renewal_window_secs)),
            info.pending_actions
        ),
    ]
}

fn error(error: &CoreError) -> String {
    match error {
        CoreError::PeerNotFound(query) => format!("❌ Par '{}' não encontrado. Use o nick de alguém conectado ou a pubkey completa.", query),
        CoreError::NoStream(query) => format!("⚠️ Nenhuma tela ativa encontrada para '{}'. Verifique os pares ou aguarde.", query),
        CoreError::AlreadyStreaming => "Você já está transmitindo sua tela. Use /screen stop para parar.".to_string(),
        CoreError::NotStreaming => "Nenhuma transmissão de tela em andamento.".to_string(),
        CoreError::NotInVoice => "⚠️ Você não está conectado a nenhuma sala de voz.".to_string(),
        CoreError::NoSuchChannel { name, voice: true } => format!("❌ Não há sala de voz '{}' neste servidor. Veja o painel de canais.", name),
        CoreError::NoSuchChannel { name, voice: false } => format!("❌ #{} não existe neste servidor. Veja o painel de canais.", name),
        CoreError::NoGroupKey => {
            "🔐 Aguardando a chave do grupo deste servidor (o dono precisa estar online para admitir você).".to_string()
        }
        CoreError::BannedHere => "⛔ Você está banido deste servidor: os outros membros ignoram suas mensagens.".to_string(),
        CoreError::NotOnAllowList => "🔒 Servidor fechado e você não está na allow-list: suas mensagens são ignoradas.".to_string(),
        CoreError::InLobby => "Você está no 🌐 Lobby. Entre num servidor primeiro (/server list, /server switch <nome>).".to_string(),
        CoreError::SelfModeration => "❌ Você não pode moderar a si mesmo.".to_string(),
        CoreError::NoInvite => "Nenhum convite recebido ainda. Peça para alguém usar /server invite no Lobby.".to_string(),
        CoreError::ServerNotFound(query) => format!("❌ Servidor '{}' não encontrado. Veja /server list.", query),
        CoreError::Server(message) | CoreError::File(message) | CoreError::Network(message) => format!("❌ {}", message),
        CoreError::Io { context, message } => format!("❌ Erro ao ler '{}': {}", context, message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p2p_core::runtime::ServerListEntry;

    #[test]
    fn test_every_kind_of_event_has_sensible_text() {
        assert_eq!(describe(&CoreEvent::ChannelEntered { space: SpaceInfo::Lobby, channel: "geral".into() }), vec!["🚀 🌐 Lobby #geral"]);
        assert!(describe(&CoreEvent::Voice(VoiceEvent::Speaking { nick: "Alice".into(), speaking: true }))[0].contains("Alice começou a falar"));
        assert!(describe(&CoreEvent::Screen(ScreenEvent::StreamAvailable { stream_id: "s".into(), nick: "Alice".into() }))[0]
            .contains("Nova tela compartilhada por 'Alice'"));
        let list = describe(&CoreEvent::Server(ServerNotice::List {
            lobby_current: false,
            servers: vec![ServerListEntry {
                id: "ab".repeat(32),
                name: "Guilda".into(),
                current: true,
                owner: true,
                moderator_level: None,
                pending: false,
                closed: true,
                banned: false,
            }],
        }));
        assert_eq!(list.len(), 2);
        assert!(list[1].starts_with("▶ 🏰 Guilda") && list[1].contains("[dono, fechado]"), "{}", list[1]);
        assert!(describe(&CoreEvent::Error(CoreError::InLobby))[0].contains("Lobby"));
        assert!(describe(&CoreEvent::ChatMessage {
            channel: "geral".into(),
            author: "a".into(),
            author_pubkey: "p".into(),
            text: "t".into(),
            timestamp: 0
        })
        .is_empty());
    }

    #[test]
    fn test_utc_dates_and_sizes() {
        assert_eq!(fmt_utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(fmt_utc(1_798_000_000), "2026-12-23 04:26 UTC");
        assert_eq!(human_size(3 * 1024 * 1024 + 300_000), "3.3 MB");
        assert_eq!(human_size(512), "512 B");
    }
}
