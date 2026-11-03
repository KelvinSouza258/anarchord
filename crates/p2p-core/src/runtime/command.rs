//! Comandos que a interface (TUI, GUI, daemon) manda para o core.

use crate::screen::VideoCodec;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Para onde vão os quadros da tela que o usuário está assistindo. Fila curta e limitada:
/// se a janela atrasar, os quadros excedentes são descartados. Quando a janela fecha (o
/// receptor é descartado), o core sai da transmissão sozinho.
pub type FrameSink = std::sync::mpsc::SyncSender<(VideoCodec, Vec<u8>)>;

#[derive(Debug, Serialize, Deserialize)]
pub enum CoreCommand {
    /// Mensagem de texto no canal atual
    SendMessage(String),
    /// Entra num canal de texto do espaço atual
    JoinChannel(String),
    JoinVoice(String),
    LeaveVoice,
    ToggleMute,
    ListPeers,
    ListAudioDevices,
    ListScreens,
    StartScreenShare { monitor: usize, quality: u32 },
    StopScreenShare,
    /// Assiste a transmissão de um par (nick, id da stream ou prefixo da pubkey). Sem `sink`
    /// (ex.: controle remoto), o core só conta os quadros (`ScreenEvent::FrameReceived`).
    WatchScreen {
        query: String,
        #[serde(skip)]
        sink: Option<FrameSink>,
    },
    /// Disca um endereço (ex.: `/ip4/.../p2p/<relay>/p2p-circuit/p2p/<par>`)
    Dial(String),
    /// Compartilha um arquivo na sala atual
    ShareFile(PathBuf),
    /// Oferece um arquivo só a um par
    SendFile { to: String, path: PathBuf },
    GetFile(String),
    RejectFile(String),
    Unshare(String),
    ListFiles,
    Server(ServerCommand),
    /// Encerra o nó (desanuncia nos trackers e emite `CoreEvent::Stopped`)
    Shutdown,
}

/// Comandos de servidor
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub enum ServerCommand {
    Create(String),
    Join(String),
    /// Entra no servidor do último convite recebido no chat
    Accept,
    Leave,
    List,
    Info,
    /// Troca de espaço: nome ou id de servidor, ou "lobby"
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
