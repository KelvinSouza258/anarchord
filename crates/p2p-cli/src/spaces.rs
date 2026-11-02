//! Comandos de servidor e canal ativo da interface.
//! A lógica de servidores (manifestos, moderação, persistência) fica no core (`p2p_core::community`);
//! aqui só ficam o parser dos comandos e a troca de inscrição de tópico ao mudar de canal.

use libp2p::gossipsub::{self, IdentTopic};
use p2p_core::community::{channel_topic, parse_duration, Space};

/// Comandos `/server ...` (e o atalho `/lobby`)
#[derive(Debug, PartialEq, Clone)]
pub enum ServerCommand {
    Create(String),
    Join(String),
    /// Entra no servidor do último convite recebido no chat
    Accept,
    Leave,
    List,
    Info,
    Switch(String),
    Invite,
    History,
    AddChannel { name: String, voice: bool },
    RemoveChannel(String),
    /// Emite certificado de moderador (nível 1 = mais autoridade abaixo do dono)
    AddModerator { target: String, level: u8 },
    /// Revoga os certificados de moderador
    RemoveModerator(String),
    /// Ban com duração em segundos (`None` = permanente)
    Ban { target: String, duration: Option<u64>, reason: String },
    Unban(String),
    /// Allow-list (servidor fechado)
    Allow(String),
    Disallow(String),
    Close,
    Open,
    /// Validade dos certificados e janela de renovação, em segundos
    Policy { validity: u64, renewal_window: u64 },
    Help,
}

pub const SERVER_HELP: &str = "Comandos: /server create <nome> | join <id> | accept | list | switch <nome|id|lobby> | info | history \
| invite | channel add <nome> [voz] | channel remove <nome> | mod add <par> [nível] | mod remove <par> \
| ban <par> [30m|12h|3d|2w|perm] [motivo] | unban <par> | allow <par> | disallow <par> | close | open \
| policy <validade> <janela> (ex.: 7d 2d) | leave  (atalho: /lobby)";

/// Texto do convite publicado no chat. Quem recebe usa `/server accept`.
pub fn invite_text(server_name: &str, server_id: &str) -> String {
    format!("📨 Convite para o servidor '{}'. Para entrar: /server accept  (ou /server join {})", server_name, server_id)
}

/// Se a mensagem de chat contém um convite (`/server join <id>`), devolve o id do servidor
pub fn parse_invite(text: &str) -> Option<String> {
    let rest = text.split("/server join ").nth(1)?;
    let id: String = rest.chars().take_while(|c| c.is_ascii_hexdigit()).collect();
    p2p_core::community::is_valid_server_id(&id).then_some(id)
}

/// Interpreta o que vem depois de `/server` (já sem o prefixo)
pub fn parse_server_command(rest: &str) -> ServerCommand {
    let rest = rest.trim();
    let (cmd, args) = rest.split_once(char::is_whitespace).map_or((rest, ""), |(c, a)| (c, a.trim()));
    let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_string());
    match cmd {
        "create" => non_empty(args).map(ServerCommand::Create),
        "join" => non_empty(args).map(ServerCommand::Join),
        "accept" => Some(ServerCommand::Accept),
        "leave" => Some(ServerCommand::Leave),
        "list" | "ls" => Some(ServerCommand::List),
        "info" => Some(ServerCommand::Info),
        "switch" | "go" => non_empty(args).map(ServerCommand::Switch),
        "invite" => Some(ServerCommand::Invite),
        "history" | "historico" => Some(ServerCommand::History),
        "channel" => {
            let mut parts = args.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some("add"), Some(name), kind) => Some(ServerCommand::AddChannel {
                    name: name.trim_start_matches('#').to_string(),
                    voice: matches!(kind, Some("voz" | "voice")),
                }),
                (Some("remove"), Some(name), None) => Some(ServerCommand::RemoveChannel(name.trim_start_matches('#').to_string())),
                _ => None,
            }
        }
        "mod" => {
            let mut parts = args.split_whitespace();
            match (parts.next(), parts.next(), parts.next()) {
                (Some("add"), Some(target), level) => match level.map(str::parse::<u8>) {
                    None => Some(ServerCommand::AddModerator { target: target.to_string(), level: 1 }),
                    Some(Ok(level)) if level >= 1 => Some(ServerCommand::AddModerator { target: target.to_string(), level }),
                    _ => None,
                },
                (Some("remove"), Some(target), None) => Some(ServerCommand::RemoveModerator(target.to_string())),
                _ => None,
            }
        }
        "ban" => {
            let mut parts = args.splitn(3, char::is_whitespace);
            let target = parts.next().unwrap_or_default();
            let second = parts.next().unwrap_or_default();
            let rest = parts.next().unwrap_or_default();
            // O segundo argumento é a duração, se parecer uma; senão já é o motivo
            let (duration, reason) = match parse_duration(second) {
                Some(duration) => (duration, rest.trim().to_string()),
                None => (None, format!("{} {}", second, rest).trim().to_string()),
            };
            non_empty(target).map(|target| ServerCommand::Ban { target, duration, reason })
        }
        "unban" => non_empty(args).map(ServerCommand::Unban),
        "allow" => non_empty(args).map(ServerCommand::Allow),
        "disallow" => non_empty(args).map(ServerCommand::Disallow),
        "close" => Some(ServerCommand::Close),
        "open" => Some(ServerCommand::Open),
        "policy" => {
            let mut parts = args.split_whitespace();
            match (parts.next().and_then(parse_duration), parts.next().and_then(parse_duration)) {
                (Some(Some(validity)), Some(Some(renewal_window))) if renewal_window < validity => {
                    Some(ServerCommand::Policy { validity, renewal_window })
                }
                _ => None,
            }
        }
        _ => None,
    }
    .unwrap_or(ServerCommand::Help)
}

/// Canal de texto em que o usuário está (espaço + nome + tópico inscrito)
pub struct ActiveChannel {
    pub space: Space,
    pub channel: String,
    pub topic: IdentTopic,
}

impl ActiveChannel {
    pub fn new(space: Space, channel: String) -> Self {
        let topic = IdentTopic::new(channel_topic(&space, &channel));
        Self { space, channel, topic }
    }

    /// Sai do tópico atual e entra no do novo canal. Não faz nada se já estiver nele.
    pub fn switch(
        &mut self,
        gossipsub: &mut gossipsub::Behaviour,
        space: Space,
        channel: String,
    ) -> Result<(), gossipsub::SubscriptionError> {
        if self.space == space && self.channel == channel {
            return Ok(());
        }
        let next = ActiveChannel::new(space, channel);
        gossipsub.subscribe(&next.topic)?;
        let _ = gossipsub.unsubscribe(&self.topic);
        *self = next;
        Ok(())
    }

    pub fn server_id(&self) -> Option<&str> {
        match &self.space {
            Space::Server(id) => Some(id),
            Space::Lobby => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_server_commands() {
        assert_eq!(parse_server_command("create Rust Guild"), ServerCommand::Create("Rust Guild".into()));
        assert_eq!(parse_server_command("join abc123"), ServerCommand::Join("abc123".into()));
        assert_eq!(parse_server_command("accept"), ServerCommand::Accept);
        assert_eq!(parse_server_command("list"), ServerCommand::List);
        assert_eq!(parse_server_command("switch lobby"), ServerCommand::Switch("lobby".into()));
        assert_eq!(parse_server_command("channel add #jogos"), ServerCommand::AddChannel { name: "jogos".into(), voice: false });
        assert_eq!(parse_server_command("channel add papo voz"), ServerCommand::AddChannel { name: "papo".into(), voice: true });
        assert_eq!(parse_server_command("mod add Bob"), ServerCommand::AddModerator { target: "Bob".into(), level: 1 });
        assert_eq!(parse_server_command("mod add Bob 2"), ServerCommand::AddModerator { target: "Bob".into(), level: 2 });
        assert_eq!(parse_server_command("mod remove Bob"), ServerCommand::RemoveModerator("Bob".into()));
        assert_eq!(
            parse_server_command("ban Bob spam no canal"),
            ServerCommand::Ban { target: "Bob".into(), duration: None, reason: "spam no canal".into() }
        );
        assert_eq!(
            parse_server_command("ban Bob 3d spam"),
            ServerCommand::Ban { target: "Bob".into(), duration: Some(3 * 86_400), reason: "spam".into() }
        );
        assert_eq!(parse_server_command("ban Bob perm"), ServerCommand::Ban { target: "Bob".into(), duration: None, reason: String::new() });
        assert_eq!(parse_server_command("ban Bob"), ServerCommand::Ban { target: "Bob".into(), duration: None, reason: String::new() });
        assert_eq!(parse_server_command("unban Bob"), ServerCommand::Unban("Bob".into()));
        assert_eq!(parse_server_command("allow Carol"), ServerCommand::Allow("Carol".into()));
        assert_eq!(parse_server_command("disallow Carol"), ServerCommand::Disallow("Carol".into()));
        assert_eq!(parse_server_command("close"), ServerCommand::Close);
        assert_eq!(parse_server_command("open"), ServerCommand::Open);
        assert_eq!(parse_server_command("history"), ServerCommand::History);
        assert_eq!(parse_server_command("channel remove #jogos"), ServerCommand::RemoveChannel("jogos".into()));
        assert_eq!(
            parse_server_command("policy 7d 2d"),
            ServerCommand::Policy { validity: 7 * 86_400, renewal_window: 2 * 86_400 }
        );
    }

    #[test]
    fn test_invite_roundtrip() {
        let id = "ab".repeat(32);
        assert_eq!(parse_invite(&invite_text("Rust Guild", &id)), Some(id.clone()));
        assert_eq!(parse_invite(&format!("entra aí: /server join {} valeu", id)), Some(id));
        assert_eq!(parse_invite("/server join abc"), None, "id curto não é convite");
        assert_eq!(parse_invite("bom dia"), None);
    }

    #[test]
    fn test_incomplete_commands_show_help() {
        for input in ["", "create", "join", "channel", "channel add", "mod", "mod add", "mod add Bob 0", "ban", "policy 2d 7d", "policy 7d", "xyz"] {
            assert_eq!(parse_server_command(input), ServerCommand::Help, "entrada: {:?}", input);
        }
    }
}
