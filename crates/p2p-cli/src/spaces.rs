//! Texto dos comandos `/server ...` -> `ServerCommand` do core.

use p2p_core::community::parse_duration;
use p2p_core::runtime::ServerCommand;

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
                (Some("add"), Some(target), None) => Some(ServerCommand::AddModerator { target: target.to_string() }),
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
        "revoke" => non_empty(args).map(ServerCommand::Revoke),
        "tsa" => {
            let mut parts = args.split_whitespace();
            match (parts.next(), parts.next(), parts.next(), parts.next()) {
                (Some("add"), Some(name), Some(url), Some(key)) => {
                    Some(ServerCommand::AddTsa { name: name.to_string(), url: url.to_string(), public_key_b64: key.to_string() })
                }
                (Some("remove"), Some(name), None, None) => Some(ServerCommand::RemoveTsa(name.to_string())),
                _ => None,
            }
        }
        "close" => Some(ServerCommand::Close),
        "open" => Some(ServerCommand::Open),
        "rotate-key" | "rotate" => Some(ServerCommand::RotateKey),
        "passport" => {
            let mut parts = args.split_whitespace();
            match parts.next() {
                Some("issue") => {
                    let target = parts.next().unwrap_or_default();
                    let mut moderator = false;
                    let mut duration = None;
                    for arg in parts {
                        match arg {
                            "mod" | "moderador" => moderator = true,
                            "membro" | "member" => moderator = false,
                            other => duration = parse_duration(other).flatten(),
                        }
                    }
                    non_empty(target).map(|target| ServerCommand::IssuePassport { target, moderator, duration })
                }
                Some("show") => Some(ServerCommand::ShowPassport),
                Some("flatten") => Some(ServerCommand::FlattenPassport),
                _ => None,
            }
        }
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
        assert_eq!(parse_server_command("mod add Bob"), ServerCommand::AddModerator { target: "Bob".into() });
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
        assert_eq!(parse_server_command("revoke Carol"), ServerCommand::Revoke("Carol".into()));
        assert_eq!(
            parse_server_command("tsa add Minha https://tsa.exemplo/tsr MHYw"),
            ServerCommand::AddTsa { name: "Minha".into(), url: "https://tsa.exemplo/tsr".into(), public_key_b64: "MHYw".into() }
        );
        assert_eq!(parse_server_command("tsa remove FreeTSA"), ServerCommand::RemoveTsa("FreeTSA".into()));
        assert_eq!(parse_server_command("close"), ServerCommand::Close);
        assert_eq!(parse_server_command("open"), ServerCommand::Open);
        assert_eq!(parse_server_command("rotate-key"), ServerCommand::RotateKey);
        assert_eq!(parse_server_command("rotate"), ServerCommand::RotateKey);
        assert_eq!(parse_server_command("history"), ServerCommand::History);
        assert_eq!(parse_server_command("channel remove #jogos"), ServerCommand::RemoveChannel("jogos".into()));
        assert_eq!(
            parse_server_command("policy 7d 2d"),
            ServerCommand::Policy { validity: 7 * 86_400, renewal_window: 2 * 86_400 }
        );
        assert_eq!(
            parse_server_command("passport issue Carol 3d"),
            ServerCommand::IssuePassport { target: "Carol".into(), moderator: false, duration: Some(3 * 86_400) }
        );
        assert_eq!(
            parse_server_command("passport issue Bob mod"),
            ServerCommand::IssuePassport { target: "Bob".into(), moderator: true, duration: None }
        );
        assert_eq!(parse_server_command("passport show"), ServerCommand::ShowPassport);
        assert_eq!(parse_server_command("passport flatten"), ServerCommand::FlattenPassport);
    }

    #[test]
    fn test_incomplete_commands_show_help() {
        for input in ["", "create", "join", "channel", "channel add", "mod", "mod add", "mod add Bob 2", "tsa add x", "ban", "policy 2d 7d", "policy 7d", "xyz"] {
            assert_eq!(parse_server_command(input), ServerCommand::Help, "entrada: {:?}", input);
        }
    }
}
