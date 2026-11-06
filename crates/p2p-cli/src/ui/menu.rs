//! Menus da TUI (menu principal e menus de contexto) e caixas de diálogo.
//! Cada item gera um comando de texto igual ao que o usuário digitaria, então o backend não
//! precisa saber de menus.

/// Estado resumido de um arquivo exibido no popup de `/files` e usado no autocompletar da TUI
#[derive(Debug, Clone, PartialEq)]
pub enum FileUiState {
    Offered,
    Downloading { progress: f32, peers: usize },
    Seeding,
}

/// Arquivo exibido no popup de `/files` e registrado para autocompletar com `Tab`
#[derive(Debug, Clone, PartialEq)]
pub struct FileUiEntry {
    /// ID curto do manifesto (`cid.short()`, ex.: `"bafk1234"`)
    pub id: String,
    pub name: String,
    pub size: String,
    pub from: String,
    pub state: FileUiState,
}

/// Amigo exibido nos menus e painel lateral (enviado pelo backend em `UiEvent::FriendsChanged`)
#[derive(Debug, Clone, PartialEq)]
pub struct FriendUiEntry {
    pub public_key: String,
    pub display_name: String,
    pub online: bool,
    pub state: p2p_core::identity::FriendState,
}

/// Servidor exibido nos menus (enviado pelo backend em `UiEvent::ServersChanged`)
#[derive(Debug, Clone, PartialEq)]
pub struct ServerEntry {
    pub name: String,
    /// Id completo do servidor (usado em `/server switch <id>`)
    pub id: String,
    pub current: bool,
    pub owner: bool,
    pub pending: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum MenuAction {
    /// Executa o comando como se tivesse sido digitado
    Run(String),
    /// Pergunta um texto e executa `template` com `{}` trocado pela resposta
    Ask { prompt: String, template: String },
    /// Abre um submenu
    Submenu(Menu),
    /// Abre a tela de ajuda
    Help,
}

#[derive(Debug, Clone, PartialEq)]
pub struct MenuItem {
    pub label: String,
    pub action: MenuAction,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Menu {
    pub title: String,
    pub items: Vec<MenuItem>,
    pub selected: usize,
}

fn run(label: impl Into<String>, command: impl Into<String>) -> MenuItem {
    MenuItem { label: label.into(), action: MenuAction::Run(command.into()) }
}

fn ask(label: &str, prompt: impl Into<String>, template: impl Into<String>) -> MenuItem {
    MenuItem { label: label.to_string(), action: MenuAction::Ask { prompt: prompt.into(), template: template.into() } }
}

impl Menu {
    pub fn new(title: impl Into<String>, items: Vec<MenuItem>) -> Self {
        Self { title: title.into(), items, selected: 0 }
    }

    pub fn up(&mut self) {
        self.selected = if self.selected == 0 { self.items.len().saturating_sub(1) } else { self.selected - 1 };
    }

    pub fn down(&mut self) {
        self.selected = if self.selected + 1 >= self.items.len() { 0 } else { self.selected + 1 };
    }

    pub fn current(&self) -> Option<&MenuItem> {
        self.items.get(self.selected)
    }

    #[cfg(test)]
    pub fn find(&self, label_start: &str) -> Option<usize> {
        self.items.iter().position(|i| i.label.contains(label_start))
    }
}

/// O que a interface sabe do contexto atual, para montar menus que fazem sentido
pub struct MenuContext<'a> {
    pub in_server: bool,
    pub in_voice: bool,
    pub servers: &'a [ServerEntry],
    pub friends: &'a [FriendUiEntry],
}

/// Menu principal (F1)
pub fn main_menu(ctx: &MenuContext) -> Menu {
    let mut items = vec![
        ask("🏰 Criar servidor…", "Nome do novo servidor", "/server create {}"),
        run("📨 Aceitar último convite", "/server accept"),
        MenuItem { label: "🔀 Trocar de espaço ▸".into(), action: MenuAction::Submenu(spaces_menu(ctx.servers)) },
        MenuItem { label: "👥 Amigos e DMs ▸".into(), action: MenuAction::Submenu(friends_menu(ctx.friends)) },
        ask("🔗 Entrar em servidor pelo id…", "Id do servidor (64 caracteres)", "/server join {}"),
    ];
    if ctx.in_server {
        items.extend([
            run("📨 Convidar para este servidor", "/server invite"),
            ask("➕ Criar canal de texto…", "Nome do canal", "/server channel add {}"),
            ask("➕ Criar sala de voz…", "Nome da sala de voz", "/server channel add {} voz"),
            run("ℹ️ Informações do servidor", "/server info"),
            run("📜 Histórico de alterações", "/server history"),
            run("🔒 Fechar servidor (allow-list)", "/server close"),
            run("🔓 Abrir servidor", "/server open"),
            ask("⏳ Política de certificados…", "Validade e janela de renovação (ex.: 7d 2d)", "/server policy {}"),
            run("🚪 Sair deste servidor", "/server leave"),
        ]);
    } else {
        items.push(ask("# Entrar em canal do Lobby…", "Nome do canal", "/join {}"));
    }
    if ctx.in_voice {
        items.push(run("🔇 Sair da sala de voz", "/voice leave"));
    } else {
        items.push(ask("🔊 Entrar em sala de voz…", "Nome da sala de voz", "/voice join {}"));
    }
    items.extend([
        run("🎙️ Mutar / desmutar microfone", "/mute"),
        ask("📎 Compartilhar arquivo na sala…", "Caminho do arquivo", "/share \"{}\""),
        run("📁 Arquivos (ofertas, downloads e compartilhados)", "/files"),
        run("📺 Compartilhar minha tela", "/screen start"),
        run("⏹️ Parar compartilhamento de tela", "/screen stop"),
        run("👥 Pares conectados", "/peers"),
        run("🎧 Dispositivos de áudio", "/devices"),
        MenuItem { label: "❓ Ajuda e atalhos".into(), action: MenuAction::Help },
        run("⏻ Sair do Anarchord", "/quit"),
    ]);
    Menu::new(" Menu ", items)
}

/// Submenu com o Lobby e os servidores conhecidos
pub fn spaces_menu(servers: &[ServerEntry]) -> Menu {
    let in_server = servers.iter().any(|s| s.current);
    let mut items = vec![run(if in_server { "  🌐 Lobby" } else { "▶ 🌐 Lobby" }, "/server switch lobby")];
    for s in servers {
        let mut tags = Vec::new();
        if s.owner {
            tags.push("dono");
        }
        if s.pending {
            tags.push("aguardando");
        }
        let tags = if tags.is_empty() { String::new() } else { format!(" [{}]", tags.join(", ")) };
        let label = format!("{} 🏰 {}{}", if s.current { "▶" } else { " " }, s.name, tags);
        items.push(MenuItem { label, action: MenuAction::Run(format!("/server switch {}", s.id)) });
    }
    Menu::new(" Trocar de espaço ", items)
}

/// Submenu de Amigos e Mensagens Diretas (DMs)
pub fn friends_menu(friends: &[FriendUiEntry]) -> Menu {
    let mut items = vec![
        ask("➕ Adicionar amigo…", "Pubkey (64 hex) ou nick conectado [apelido opcional]", "/friend add {}"),
        ask("💬 Enviar DM rápida…", "Destinatário e mensagem (ex.: Bob olá!)", "/dm {}"),
        run("📋 Listar amigos no log (/friends)", "/friends"),
    ];
    for f in friends {
        let (icon, sub_items) = match f.state {
            p2p_core::identity::FriendState::Confirmed => {
                let icon = if f.online { "🟢" } else { "⚪" };
                let items = vec![
                    run("💬 Abrir conversa direta (DM)", format!("/dm open {}", f.display_name)),
                    ask("📨 Enviar mensagem direta…", format!("Mensagem para {}", f.display_name), format!("/dm {} {{}}", f.display_name)),
                    run("💔 Remover dos amigos", format!("/friend remove {}", f.public_key)),
                ];
                (icon, items)
            }
            p2p_core::identity::FriendState::PendingIncoming => {
                let icon = "📩";
                let items = vec![
                    run("✅ Aceitar pedido de amizade", format!("/friend accept {}", f.public_key)),
                    run("❌ Rejeitar pedido de amizade", format!("/friend reject {}", f.public_key)),
                    run("💔 Remover / ignorar", format!("/friend remove {}", f.public_key)),
                ];
                (icon, items)
            }
            p2p_core::identity::FriendState::PendingOutgoing => {
                let icon = "⏳";
                let items = vec![
                    run("🔄 Reenviar pedido de amizade", format!("/friend resend {}", f.public_key)),
                    run("💔 Cancelar / remover pedido", format!("/friend remove {}", f.public_key)),
                ];
                (icon, items)
            }
            p2p_core::identity::FriendState::Rejected => {
                let icon = "🚫";
                let items = vec![
                    run("🔄 Reenviar pedido de amizade", format!("/friend resend {}", f.public_key)),
                    run("💔 Remover da lista", format!("/friend remove {}", f.public_key)),
                ];
                (icon, items)
            }
        };
        let short_pk = if f.public_key.len() >= 8 { &f.public_key[..8] } else { &f.public_key };
        let label = format!("{} {} ({}) ▸", icon, f.display_name, short_pk);
        let sub = Menu::new(format!(" {} ", f.display_name), sub_items);
        items.push(MenuItem { label, action: MenuAction::Submenu(sub) });
    }
    Menu::new(" Amigos e DMs ", items)
}

/// Menu de contexto de um membro da sala
pub fn member_menu(nick: &str, in_server: bool) -> Menu {
    let mut items = vec![
        run("💬 Abrir conversa direta (DM)", format!("/dm open {}", nick)),
        ask("📨 Enviar mensagem direta…", format!("Mensagem privada para {}", nick), format!("/dm {} {{}}", nick)),
        ask("📁 Enviar arquivo…", format!("Caminho do arquivo para {}", nick), format!("/send {} \"{{}}\"", nick)),
        run("📺 Assistir tela", format!("/screen watch {}", nick)),
        run("💚 Adicionar aos amigos", format!("/friend add {}", nick)),
        run("💔 Remover dos amigos", format!("/friend remove {}", nick)),
    ];
    if in_server {
        items.extend([
            MenuItem { label: "🔨 Banir ▸".into(), action: MenuAction::Submenu(ban_menu(nick)) },
            run("🕊️ Desbanir", format!("/server unban {}", nick)),
            run("🛡️ Tornar moderador", format!("/server mod add {}", nick)),
            run("🛡️ Remover moderador", format!("/server mod remove {}", nick)),
            run("✅ Admitir (servidor fechado)", format!("/server allow {}", nick)),
            run("🚫 Remover da allow-list", format!("/server disallow {}", nick)),
        ]);
    }
    Menu::new(format!(" {} ", nick), items)
}

/// Duração do ban; cada opção pergunta o motivo (opcional)
pub fn ban_menu(nick: &str) -> Menu {
    let option = |label: &str, duration: &str| {
        ask(label, format!("Motivo do ban de {} (opcional)", nick), format!("/server ban {} {} {{}}", nick, duration))
    };
    Menu::new(
        format!(" Banir {} ", nick),
        vec![option("⏱️ 1 hora", "1h"), option("📅 1 dia", "1d"), option("🗓️ 7 dias", "7d"), option("⛔ Permanente", "perm")],
    )
}

/// Menu de contexto de um canal do painel de canais
pub fn channel_menu(name: &str, is_voice: bool) -> Menu {
    let items = if is_voice {
        vec![run("🔊 Entrar na sala de voz", format!("/voice join {}", name)), run("🔇 Sair da sala de voz", "/voice leave")]
    } else {
        vec![run("# Entrar no canal", format!("/join {}", name))]
    };
    Menu::new(format!(" {}{} ", if is_voice { "🔊 " } else { "#" }, name), items)
}

/// Popup interativo e clicável de arquivos (`/files`), permitindo clicar num arquivo para
/// baixar (`/get`), recusar (`/reject`) ou parar de compartilhar (`/unshare`).
pub fn files_menu(files: &[FileUiEntry]) -> Menu {
    let mut items = Vec::new();
    for f in files {
        let (icon, status, actions) = match &f.state {
            FileUiState::Offered => (
                "📥",
                format!("oferecido por {} · clique para baixar", f.from),
                vec![
                    run(format!("📥 Baixar '{}' (/get {})", f.name, f.id), format!("/get {}", f.id)),
                    run(format!("❌ Recusar oferta (/reject {})", f.id), format!("/reject {}", f.id)),
                ],
            ),
            FileUiState::Downloading { progress, peers } => (
                "⏳",
                format!("baixando {:.0}% ({} par(es))", progress * 100.0, peers),
                vec![
                    run(format!("🛑 Cancelar download (/unshare {})", f.id), format!("/unshare {}", f.id)),
                ],
            ),
            FileUiState::Seeding => (
                "📤",
                "compartilhando".to_string(),
                vec![
                    run(format!("🛑 Parar de compartilhar (/unshare {})", f.id), format!("/unshare {}", f.id)),
                ],
            ),
        };
        let size_part = if f.size.is_empty() { String::new() } else { format!(" ({})", f.size) };
        let label = format!("{} [{}] {}{} — {} ▸", icon, f.id, f.name, size_part, status);
        let sub = Menu::new(format!(" 📁 {} [{}] ", f.name, f.id), actions);
        items.push(MenuItem { label, action: MenuAction::Submenu(sub) });
    }
    items.push(ask("📎 Compartilhar novo arquivo na sala…", "Caminho do arquivo", "/share \"{}\""));
    let title = if files.is_empty() {
        " 📁 Arquivos (nenhum arquivo ativo) ".to_string()
    } else {
        format!(" 📁 Arquivos ({}) — clique ou Enter para escolher ", files.len())
    };
    Menu::new(title, items)
}

/// Comando para entrar num canal ao clicar nele
pub fn channel_command(name: &str, is_voice: bool) -> String {
    if is_voice {
        format!("/voice join {}", name)
    } else {
        format!("/join {}", name)
    }
}

/// Texto da tela de ajuda
pub const HELP_LINES: &[&str] = &[
    "ATALHOS",
    "  F1 ou Ctrl+K     abre o menu principal (Servidores, Amigos, DMs, Voz)",
    "  Clique           membro/amigo: ações (DM, arquivo, tela, amigo) · canal: entrar",
    "  ↑ / ↓            histórico do que você digitou",
    "  ← → Home End     move o cursor · Delete apaga à frente",
    "  Tab              completa comandos e nicks",
    "  F2               alterna entre as abas Chat e Sistema (ou clique no nome da aba)",
    "  PgUp / PgDn      rola a aba atual (roda do mouse também)",
    "  Esc              fecha menus e diálogos · Ctrl+C sai",
    "",
    "COMANDOS",
    "  /join <canal>            /voice join <sala>     /voice leave     /mute",
    "  /friend add <pk|nick> [apelido]   /friend remove <pk|apelido>    /friends",
    "  /dm open <par>           /dm <par> <mensagem> [--ttl 2h|7d]",
    "  /config show             /config set <chave> <valor>",
    "  /firewall                /firewall unblock <par>",
    "  /share <arquivo>         compartilha na sala atual (quem quiser baixa com /get)",
    "  /send <par> <arquivo>    /get <id>      /reject <id>      /files      /unshare <id>",
    "  /screen start [monitor] [720|1080]   /screen stop   /screen watch <par>",
    "  /server create <nome>    /server accept         /server switch <nome|lobby>",
    "  /server invite           /server channel add <nome> [voz]",
    "  /server mod add <par>    /server ban <par> [motivo]   /server unban <par>",
    "  /server list · info · leave      /lobby      /peers      /devices      /quit",
];

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, current: bool) -> ServerEntry {
        ServerEntry { name: name.into(), id: format!("{}-id", name), current, owner: false, pending: false }
    }

    #[test]
    fn test_main_menu_depends_on_context() {
        let lobby = main_menu(&MenuContext { in_server: false, in_voice: false, servers: &[], friends: &[] });
        assert!(lobby.find("Criar servidor").is_some());
        assert!(lobby.find("Amigos e DMs").is_some());
        assert!(lobby.find("Convidar").is_none(), "no Lobby não há servidor para convidar");
        assert!(lobby.find("Entrar em sala de voz").is_some());

        let server = main_menu(&MenuContext { in_server: true, in_voice: true, servers: &[], friends: &[] });
        assert!(server.find("Convidar").is_some());
        assert!(server.find("Criar canal de texto").is_some());
        assert!(server.find("Sair da sala de voz").is_some());
    }

    #[test]
    fn test_spaces_menu_marks_current_space() {
        let menu = spaces_menu(&[entry("Guild", true), entry("Outro", false)]);
        assert_eq!(menu.items.len(), 3);
        assert_eq!(menu.items[0].label, "  🌐 Lobby");
        assert!(menu.items[1].label.starts_with("▶ 🏰 Guild"));
        assert_eq!(menu.items[2].action, MenuAction::Run("/server switch Outro-id".into()));
    }

    #[test]
    fn test_member_menu_moderation_only_in_server() {
        assert!(member_menu("Bob", false).find("Banir").is_none());
        let menu = member_menu("Bob", true);
        let ban = &menu.items[menu.find("Banir").unwrap()];
        let MenuAction::Submenu(durations) = &ban.action else { panic!("Banir abre as durações") };
        let day = &durations.items[durations.find("1 dia").unwrap()];
        assert_eq!(day.action, MenuAction::Ask { prompt: "Motivo do ban de Bob (opcional)".into(), template: "/server ban Bob 1d {}".into() });
        assert!(menu.find("Remover moderador").is_some());
        assert!(menu.find("Admitir").is_some());
        let file = &menu.items[menu.find("Enviar arquivo").unwrap()];
        assert!(matches!(&file.action, MenuAction::Ask { template, .. } if template == "/send Bob \"{}\""));
    }

    #[test]
    fn test_menu_navigation_wraps() {
        let mut menu = channel_menu("voz", true);
        assert_eq!(menu.selected, 0);
        menu.up();
        assert_eq!(menu.selected, 1);
        menu.down();
        assert_eq!(menu.selected, 0);
    }
}
