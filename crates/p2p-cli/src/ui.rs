use crossterm::{
    event::{self, Event, KeyCode, KeyModifiers},
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
    input: String,
    messages: Vec<String>,
    peers: Vec<(String, String)>, // (Nick, PubKey)
    speakers: Vec<String>,        // Nomes de quem está falando agora
    file_transfer: Option<(String, f32, bool)>, // (nome, pct, is_download)
    is_muted: Arc<AtomicBool>,
}

impl TerminalUi {
    pub fn new(my_nick: String, my_pubkey: String, is_muted: Arc<AtomicBool>) -> Self {
        Self {
            my_nick,
            my_pubkey,
            current_channel: "geral".to_string(),
            input: String::new(),
            messages: vec![
                "🚀 Bem-vindo ao Anarchord P2P (100% Descentralizado)!".to_string(),
                "💡 Digite sua mensagem e pressione ENTER. Use /quit para sair.".to_string(),
            ],
            peers: Vec::new(),
            speakers: Vec::new(),
            file_transfer: None,
            is_muted,
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
        execute!(stdout, EnterAlternateScreen)?;
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
                    match evt {
                        UiEvent::ChatMessage { channel, author, text } => {
                            self.messages.push(format!("[#{}] {}: {}", channel, author, text));
                        }
                        UiEvent::SystemLog(log) => {
                            self.messages.push(format!("⚙️  {}", log));
                        }
                        UiEvent::PeerConnected { peer_id: _, nick, pubkey } => {
                            if !self.peers.iter().any(|(n, _)| n == &nick) {
                                self.peers.push((nick.clone(), pubkey));
                                self.messages.push(format!("🤝 Par conectado: {}", nick));
                            }
                        }
                        UiEvent::PeerDisconnected(peer_id) => {
                            self.messages.push(format!("👋 Par desconectado: {}", peer_id));
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

                // Processa teclado do usuário de forma não bloqueante
                _ = event_interval.tick() => {
                    while event::poll(std::time::Duration::from_millis(0))? {
                        if let Event::Key(key) = event::read()? {
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
                    }
                }
            }
        }
    }

    fn draw_ui(&self, f: &mut ratatui::Frame) {
        let size = f.area();

        // Divide a tela em 3 áreas verticais: Título/Topo, Corpo Central e Barra de Entrada
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(5),    // Main Body
                Constraint::Length(3), // Input Bar
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
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(main_chunks[1]);

        // Lista de Membros
        let peer_items: Vec<ListItem> = self
            .peers
            .iter()
            .map(|(nick, pk)| {
                let short_pk = if pk.len() >= 6 { &pk[..6] } else { pk };
                ListItem::new(Line::from(vec![
                    Span::styled("🟢 ", Style::default().fg(Color::Green)),
                    Span::styled(nick.clone(), Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
                    Span::styled(format!(" ({})", short_pk), Style::default().fg(Color::DarkGray)),
                ]))
            })
            .collect();

        let peers_list = List::new(peer_items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Pares Online ({}) ", self.peers.len())),
        );
        f.render_widget(peers_list, side_chunks[0]);

        // Atividade de Voz
        let voice_items: Vec<ListItem> = if self.speakers.is_empty() {
            vec![ListItem::new(Span::styled("  (Silêncio na sala)", Style::default().fg(Color::DarkGray)))]
        } else {
            self.speakers
                .iter()
                .map(|name| {
                    ListItem::new(Line::from(vec![
                        Span::styled("🔊 ", Style::default().fg(Color::Cyan)),
                        Span::styled(name.clone(), Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                        Span::styled(" [Falando...]", Style::default().fg(Color::Yellow)),
                    ]))
                })
                .collect()
        };

        let voice_list = List::new(voice_items).block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Sala de Voz [🔊 geral] "),
        );
        f.render_widget(voice_list, side_chunks[1]);

        // 3. Barra de Entrada Inferior
        let input_box = Paragraph::new(format!("❯ {}", self.input))
            .style(Style::default().fg(Color::White))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Digite uma mensagem ou comando (/send <par> <arquivo>, /mute, /quit) "),
            );
        f.render_widget(input_box, chunks[2]);
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
        execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;
        Ok(())
    }
}
