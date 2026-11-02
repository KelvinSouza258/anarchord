use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers, MouseButton, MouseEventKind, EnableMouseCapture, DisableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, List, ListItem, Paragraph},
    Terminal,
};
use std::collections::{HashMap, HashSet};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Eventos enviados pelo backend P2P para atualizar a TUI
#[derive(Debug, Clone)]
pub enum UiEvent {
    /// Mensagem de chat recebida
    ChatMessage {
        channel: String,
        author: String,
        text: String,
    },
    /// Log ou notificação do sistema
    SystemLog(String),
    /// Par conectado ou atualizado (PeerId, Nickname, PubKey)
    PeerConnected {
        peer_id: String,
        nick: String,
        pubkey: String,
    },
    /// Par desconectado
    PeerDisconnected(String),
    /// Pares inscritos no tópico de um canal de texto (presença na sala)
    ChannelMembers {
        channel: String,
        members: Vec<String>,
    },
    /// Mudança de canal de texto ativo
    ChannelChanged(String),
    /// Mudança de canal de voz ativo (None se desconectado de voz)
    VoiceChannelChanged(Option<String>),
    /// Membros ativos na sala de voz atual
    VoiceRoomMembers(Vec<String>),
    /// Indicador de voz de alguém falando (Nick, energy)
    VoiceActivity {
        nick: String,
        speaking: bool,
    },
    /// Progresso de transferência de arquivo
    FileTransferProgress {
        file_name: String,
        percentage: f32,
        is_download: bool,
    },
}

/// Ações disparadas pela UI para o backend P2P
#[derive(Debug, Clone)]
pub enum UiAction {
    SendMessage(String),
    ToggleMute,
    Quit,
}

pub struct TerminalUi {
    my_nick: String,
    my_pubkey: String,
    current_channel: String,
    current_voice_channel: Option<String>,
    input: String,
    messages: Vec<String>,
    peers: Vec<(String, String, String)>, // (PeerId, Nick, PubKey) - Todo o Swarm
    voice_members: Vec<String>,           // Membros presentes na sala de voz ativa
    channel_members: HashMap<String, HashSet<String>>, // Canal -> Nomes com presença ativa
    speakers: Vec<String>,                // Nomes de quem está falando agora
    file_transfer: Option<(String, f32, bool)>, // (nome, pct, is_download)
    is_muted: Arc<AtomicBool>,
    peers_area: Rect,
    last_status_bar: String,
}

impl TerminalUi {
    pub fn new(my_nick: String, my_pubkey: String, is_muted: Arc<AtomicBool>) -> Self {
        let mut channel_members = HashMap::new();
        let mut geral_set = HashSet::new();
        geral_set.insert(my_nick.clone());
        channel_members.insert("geral".to_string(), geral_set);

        Self {
            my_nick,
            my_pubkey,
            current_channel: "geral".to_string(),
            current_voice_channel: None,
            input: String::new(),
            messages: vec![
                "🚀 Bem-vindo ao Anarchord P2P (100% Descentralizado)!".to_string(),
                "💡 Clique em um par com o mouse para iniciar o envio de arquivo, ou digite /help.".to_string(),
            ],
            peers: Vec::new(),
            voice_members: Vec::new(),
            channel_members,
            speakers: Vec::new(),
            file_transfer: None,
            is_muted,
            peers_area: Rect::default(),
            last_status_bar: "Sistema pronto. Conectado à malha P2P.".to_string(),
        }
    }

    pub async fn run(
        mut self,
        mut rx_events: UnboundedReceiver<UiEvent>,
        tx_actions: UnboundedSender<UiAction>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // Setup Terminal
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        let mut event_interval = tokio::time::interval(std::time::Duration::from_millis(50));

        loop {
            // Desenha a UI reativa
            terminal.draw(|f| {
                self.draw_ui(f);
            })?;

            tokio::select! {
                // Processa eventos da malha P2P
                Some(evt) = rx_events.recv() => {
                    self.handle_event(evt);
                }

                // Processa teclado e mouse do usuário de forma não bloqueante
                _ = event_interval.tick() => {
                    while event::poll(std::time::Duration::from_millis(0))? {
                        match event::read()? {
                            Event::Key(key) => {
                                // No Windows, crossterm gera KeyEventKind::Press e KeyEventKind::Release!
                                // Ignoramos Release para não duplicar cada clique de tecla.
                                if key.kind != KeyEventKind::Press {
                                    continue;
                                }

                                match key.code {
                                    KeyCode::Enter => {
                                        let line = std::mem::take(&mut self.input);
                                        let trimmed = line.trim();
                                        if !trimmed.is_empty() {
                                            if trimmed == "/quit" {
                                                let _ = tx_actions.send(UiAction::Quit);
                                                self.cleanup_terminal(&mut terminal)?;
                                                return Ok(());
                                            } else if trimmed == "/mute" {
                                                let _ = tx_actions.send(UiAction::ToggleMute);
                                            } else {
                                                self.messages.push(format!("[#{}] {}: {}", self.current_channel, self.my_nick, trimmed));
                                                let _ = tx_actions.send(UiAction::SendMessage(line));
                                            }
                                        }
                                    }
                                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                                        let _ = tx_actions.send(UiAction::Quit);
                                        self.cleanup_terminal(&mut terminal)?;
                                        return Ok(());
                                    }
                                    KeyCode::Char(c) => {
                                        self.input.push(c);
                                    }
                                    KeyCode::Backspace => {
                                        self.input.pop();
                                    }
                                    _ => {}
                                }
                            }
                            Event::Mouse(mouse) => {
                                if let MouseEventKind::Down(MouseButton::Left) = mouse.kind {
                                    let col = mouse.column;
                                    let row = mouse.row;

                                    // Verifica se o clique foi dentro da área da lista de pares online
                                    if col >= self.peers_area.x
                                        && col < self.peers_area.x + self.peers_area.width
                                        && row > self.peers_area.y
                                        && row < self.peers_area.y + self.peers_area.height
                                    {
                                        let index = (row - self.peers_area.y - 1) as usize;
                                        if let Some((_pid, nick, _pubkey)) = self.peers.get(index) {
                                            // Preenche a barra de input para enviar arquivo para esse par!
                                            self.input = format!("/send {} \"\"", nick);
                                            self.messages.push(format!("💡 Selecionado '{}'. Digite o caminho do arquivo entre as aspas e dê ENTER.", nick));
                                        }
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }

    /// Aplica um evento da malha P2P ao estado da UI (separado do loop para ser testável)
    fn handle_event(&mut self, evt: UiEvent) {
        match evt {
            UiEvent::ChatMessage { channel, author, text } => {
                self.messages.push(format!("[#{}] {}: {}", channel, author, text));
                self.channel_members.entry(channel.clone()).or_default().insert(author);
            }
            UiEvent::ChannelChanged(new_channel) => {
                self.current_channel = new_channel.clone();
                self.channel_members.entry(new_channel).or_default().insert(self.my_nick.clone());
            }
            UiEvent::VoiceChannelChanged(opt_channel) => {
                self.current_voice_channel = opt_channel.clone();
                if opt_channel.is_none() {
                    self.voice_members.clear();
                    self.speakers.clear();
                } else {
                    if !self.voice_members.contains(&self.my_nick) {
                        self.voice_members.push(self.my_nick.clone());
                    }
                }
            }
            UiEvent::VoiceRoomMembers(members) => {
                self.voice_members = members;
            }
            UiEvent::SystemLog(log) => {
                self.last_status_bar = log.clone();
                self.messages.push(format!("⚙️  {}", log));
            }
            UiEvent::ChannelMembers { channel, members } => {
                let set = self.channel_members.entry(channel).or_default();
                set.clear();
                set.extend(members);
                set.insert(self.my_nick.clone());
            }
            UiEvent::PeerConnected { peer_id, nick, pubkey } => {
                if let Some(pos) = self.peers.iter().position(|(pid, _, _)| pid == &peer_id) {
                    self.peers[pos] = (peer_id, nick.clone(), pubkey);
                } else {
                    self.peers.push((peer_id, nick.clone(), pubkey));
                    self.messages.push(format!("🤝 Par conectado: {}", nick));
                }
            }
            UiEvent::PeerDisconnected(peer_id) => {
                if let Some(pos) = self.peers.iter().position(|(pid, _, _)| pid == &peer_id) {
                    let (_, nick, _) = self.peers.remove(pos);
                    self.messages.push(format!("👋 Par desconectado: {}", nick));
                } else {
                    self.messages.push(format!("👋 Par desconectado: {}", peer_id));
                }
            }
            UiEvent::VoiceActivity { nick, speaking } => {
                if speaking {
                    if !self.speakers.contains(&nick) {
                        self.speakers.push(nick);
                    }
                } else {
                    self.speakers.retain(|n| n != &nick);
                }
            }
            UiEvent::FileTransferProgress { file_name, percentage, is_download } => {
                if percentage >= 100.0 {
                    self.file_transfer = None;
                    self.messages.push(format!("✅ Arquivo '{}' concluído com sucesso!", file_name));
                } else {
                    self.file_transfer = Some((file_name, percentage, is_download));
                }
            }
        }
    }

    fn draw_ui(&mut self, f: &mut ratatui::Frame) {
        let size = f.area();

        // Divide a tela em 4 áreas verticais: Título/Topo, Corpo Central, Barra de Entrada e Rodapé
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(5),    // Main Body
                Constraint::Length(3), // Input Bar
                Constraint::Length(1), // Footer Status Bar
            ])
            .split(size);

        // 1. Header Superior
        let muted_str = if self.is_muted.load(Ordering::Relaxed) {
            "🔴 [MUTADO]"
        } else {
            "🎙️  [MIC ATIVO]"
        };

        let header = Paragraph::new(Line::from(vec![
            Span::styled("⚡ ANARCHORD P2P ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(format!("| Usuário: {} ", self.my_nick), Style::default().fg(Color::Cyan)),
            Span::styled(format!("| Chave: {}... ", &self.my_pubkey[..8]), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("| Canal: #{} ", self.current_channel), Style::default().fg(Color::Green)),
            Span::styled(format!("| {}", muted_str), Style::default().fg(Color::Magenta)),
        ]))
        .block(Block::default().borders(Borders::ALL).title(" Anarchord Core v0.1.0 "));
        f.render_widget(header, chunks[0]);

        // 2. Divide o corpo em Central (Chat + Progresso) e Lateral (Membros / Voz)
        let main_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(75), // Chat Messages
                Constraint::Percentage(25), // Peers & Voice Activity
            ])
            .split(chunks[1]);

        // Se houver arquivo transferindo, divide a janela do chat para mostrar barra de progresso
        if let Some((name, pct, is_download)) = &self.file_transfer {
            let chat_chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(4), Constraint::Length(3)])
                .split(main_chunks[0]);

            self.render_messages(f, chat_chunks[0]);

            let title = if *is_download {
                format!(" 📥 Baixando arquivo: {} ", name)
            } else {
                format!(" 📤 Enviando arquivo: {} ", name)
            };

            let gauge = Gauge::default()
                .block(Block::default().borders(Borders::ALL).title(title))
                .gauge_style(Style::default().fg(Color::Green).bg(Color::DarkGray))
                .percent(*pct as u16);
            f.render_widget(gauge, chat_chunks[1]);
        } else {
            self.render_messages(f, main_chunks[0]);
        }

        // Painel Lateral de Membros e Status de Voz
        let side_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(main_chunks[1]);

        // 1. Membros da Sala de Texto Atual (#canal)
        self.peers_area = side_chunks[0];
        let current_members = self.channel_members.get(&self.current_channel);
        
        let mut room_members_items: Vec<ListItem> = Vec::new();
        let mut seen_nicks = HashSet::new();

        // Usuário atual na sala
        room_members_items.push(ListItem::new(Line::from(vec![
            Span::styled("👤 ", Style::default().fg(Color::Yellow)),
            Span::styled(format!("{} (Você)", self.my_nick), Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        ])));
        seen_nicks.insert(self.my_nick.clone());

        // Pares ativos na sala atual
        if let Some(members) = current_members {
            for nick in members {
                if seen_nicks.insert(nick.clone()) {
                    let short_pk = self.peers.iter()
                        .find(|(_, n, _)| n == nick)
                        .map(|(_, _, pk)| if pk.len() >= 6 { format!(" ({})", &pk[..6]) } else { format!(" ({})", pk) })
                        .unwrap_or_default();

                    room_members_items.push(ListItem::new(Line::from(vec![
                        Span::styled("🟢 ", Style::default().fg(Color::Green)),
                        Span::styled(nick.clone(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                        Span::styled(short_pk, Style::default().fg(Color::DarkGray)),
                    ])));
                }
            }
        }

        // Título com membros da sala e total no Swarm P2P
        let room_members_title = format!(" Membros #{} [Swarm: {}] ", self.current_channel, self.peers.len());
        let peers_list = List::new(room_members_items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(room_members_title),
        );
        f.render_widget(peers_list, side_chunks[0]);

        // 2. Painel da Sala de Voz Atual
        let voice_title = match &self.current_voice_channel {
            Some(vchan) => format!(" Sala de Voz [🔊 {}] ({}) ", vchan, self.voice_members.len()),
            None => " Sala de Voz [Desconectada] ".to_string(),
        };

        let voice_items: Vec<ListItem> = if self.current_voice_channel.is_none() {
            vec![ListItem::new(Span::styled("  Use /voice join <sala> para entrar", Style::default().fg(Color::DarkGray)))]
        } else if self.voice_members.is_empty() {
            vec![ListItem::new(Span::styled("  (Nenhum participante conectado)", Style::default().fg(Color::DarkGray)))]
        } else {
            self.voice_members
                .iter()
                .map(|name| {
                    let is_speaking = self.speakers.contains(name);
                    if is_speaking {
                        ListItem::new(Line::from(vec![
                            Span::styled("🔊 ", Style::default().fg(Color::Green)),
                            Span::styled(name.clone(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                            Span::styled(" [Falando...]", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
                        ]))
                    } else {
                        ListItem::new(Line::from(vec![
                            Span::styled("🔈 ", Style::default().fg(Color::DarkGray)),
                            Span::styled(name.clone(), Style::default().fg(Color::White)),
                            Span::styled(" [Ouvindo]", Style::default().fg(Color::DarkGray)),
                        ]))
                    }
                })
                .collect()
        };

        let voice_list = List::new(voice_items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(voice_title),
        );
        f.render_widget(voice_list, side_chunks[1]);

        // 3. Barra de Entrada
        let input_box = Paragraph::new(format!("❯ {}", self.input))
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Digite uma mensagem ou comando (/send <par> <arquivo>, /mute, /quit) "),
            );
        f.render_widget(input_box, chunks[2]);

        // Posiciona o cursor do terminal no final do texto digitado
        // x = margem esquerda (1 borda) + 2 caracteres ("❯ ") + comprimento do texto
        // y = topo do quadro de input + 1 (borda superior)
        let cursor_x = chunks[2].x + 3 + self.input.chars().count() as u16;
        let cursor_y = chunks[2].y + 1;
        f.set_cursor_position((cursor_x, cursor_y));

        // 4. Rodapé de Notificações / Status Bar (Redirecionamento de logs de sistema)
        let footer = Paragraph::new(Line::from(vec![
            Span::styled(" 📢 STATUS: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(&self.last_status_bar, Style::default().fg(Color::Cyan)),
        ]))
        .style(Style::default().bg(Color::DarkGray));
        f.render_widget(footer, chunks[3]);
    }

    fn render_messages(&self, f: &mut ratatui::Frame, area: Rect) {
        let max_lines = area.height.saturating_sub(2) as usize;
        let start = if self.messages.len() > max_lines {
            self.messages.len() - max_lines
        } else {
            0
        };

        let visible_msgs: Vec<ListItem> = self.messages[start..]
            .iter()
            .map(|m| {
                let style = if m.starts_with("⚙️") {
                    Style::default().fg(Color::DarkGray)
                } else if m.starts_with("🤝") || m.starts_with("✅") {
                    Style::default().fg(Color::Green)
                } else if m.starts_with("❌") {
                    Style::default().fg(Color::Red)
                } else {
                    Style::default().fg(Color::White)
                };
                ListItem::new(Span::styled(m.clone(), style))
            })
            .collect();

        let messages_list = List::new(visible_msgs)
            .block(Block::default().borders(Borders::ALL).title(" Chat #geral "));
        f.render_widget(messages_list, area);
    }

    fn cleanup_terminal(&self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> io::Result<()> {
        disable_raw_mode()?;
        execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
        terminal.show_cursor()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;

    fn ui_for(nick: &str) -> TerminalUi {
        TerminalUi::new(nick.to_string(), "abcdef0123".to_string(), Arc::new(AtomicBool::new(false)))
    }

    /// Renderiza a UI num terminal virtual e devolve o texto da tela
    fn render(ui: &mut TerminalUi) -> String {
        let mut terminal = Terminal::new(TestBackend::new(140, 40)).unwrap();
        terminal.draw(|f| ui.draw_ui(f)).unwrap();
        let buffer = terminal.backend().buffer();
        let width = buffer.area.width as usize;
        buffer
            .content()
            .chunks(width)
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn bob_connected() -> UiEvent {
        UiEvent::PeerConnected {
            peer_id: "12D3KooWBob".to_string(),
            nick: "Bob".to_string(),
            pubkey: "224d733c71f8".to_string(),
        }
    }

    fn members(channel: &str, nicks: &[&str]) -> UiEvent {
        UiEvent::ChannelMembers {
            channel: channel.to_string(),
            members: nicks.iter().map(|n| n.to_string()).collect(),
        }
    }

    #[test]
    fn test_own_nick_always_listed_in_room() {
        let mut ui = ui_for("Alice");
        let screen = render(&mut ui);
        assert!(screen.contains("Alice (Você)"), "{}", screen);
        assert!(screen.contains("[Swarm: 0]"), "{}", screen);
    }

    /// Regressão: par conectado e presente na sala aparece em "Membros da Sala" sem ter mandado mensagem
    #[test]
    fn test_present_peer_listed_in_room_without_chatting() {
        let mut ui = ui_for("Alice");
        ui.handle_event(bob_connected());
        ui.handle_event(members("geral", &["Bob"]));

        let screen = render(&mut ui);
        assert!(screen.contains("Bob (224d73)"), "Bob deveria estar na lista de membros:\n{}", screen);
        assert!(screen.contains("[Swarm: 1]"), "{}", screen);
    }

    #[test]
    fn test_peer_leaving_room_is_removed_from_members() {
        let mut ui = ui_for("Alice");
        ui.handle_event(bob_connected());
        ui.handle_event(members("geral", &["Bob"]));
        ui.handle_event(members("geral", &[]));

        let screen = render(&mut ui);
        assert!(!screen.contains("Bob (224d73)"), "Bob não deveria estar na lista de membros:\n{}", screen);
        assert!(screen.contains("Alice (Você)"), "{}", screen);
    }

    #[test]
    fn test_members_of_other_channel_not_shown() {
        let mut ui = ui_for("Alice");
        ui.handle_event(bob_connected());
        ui.handle_event(members("jogos", &["Bob"]));

        let screen = render(&mut ui);
        assert!(!screen.contains("Bob (224d73)"), "Bob não deveria estar na lista de membros:\n{}", screen);

        ui.handle_event(UiEvent::ChannelChanged("jogos".to_string()));
        let screen = render(&mut ui);
        assert!(screen.contains("Bob (224d73)"), "{}", screen);
        assert!(screen.contains("#jogos"), "{}", screen);
    }

    #[test]
    fn test_disconnect_updates_swarm_count_and_logs() {
        let mut ui = ui_for("Alice");
        ui.handle_event(bob_connected());
        ui.handle_event(UiEvent::PeerDisconnected("12D3KooWBob".to_string()));

        let screen = render(&mut ui);
        assert!(screen.contains("[Swarm: 0]"), "{}", screen);
        assert!(screen.contains("Par desconectado: Bob"), "{}", screen);
    }

    #[test]
    fn test_chat_message_rendered() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::ChatMessage {
            channel: "geral".to_string(),
            author: "Bob".to_string(),
            text: "olá mesh".to_string(),
        });

        let screen = render(&mut ui);
        assert!(screen.contains("Bob: olá mesh"), "{}", screen);
    }

    #[test]
    fn test_voice_room_members_rendered() {
        let mut ui = ui_for("Alice");
        ui.handle_event(UiEvent::VoiceChannelChanged(Some("sala1".to_string())));
        ui.handle_event(UiEvent::VoiceRoomMembers(vec!["Alice".to_string(), "Bob".to_string()]));

        let screen = render(&mut ui);
        assert!(screen.contains("sala1"), "{}", screen);
        assert!(screen.contains("Bob"), "{}", screen);
    }
}
