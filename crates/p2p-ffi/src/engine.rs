//! Gerenciador do ciclo de vida do motor P2P para o FFI.

use p2p_core::runtime::{Core, CoreCommand, CoreConfig, CoreEvent};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

#[derive(Debug, thiserror::Error)]
pub enum FfiError {
    #[error("Erro ao iniciar core: {0}")]
    Start(String),
    #[error("Canal de comandos fechado")]
    ChannelClosed,
    #[error("Erro de serialização/deserialização: {0}")]
    Codec(String),
}

/// Instância do motor Anarchord em execução gerenciada pela camada FFI.
pub struct FfiEngine {
    commands: UnboundedSender<CoreCommand>,
    events: UnboundedReceiver<CoreEvent>,
    listen_port: u16,
    peer_id: String,
    running: Arc<AtomicBool>,
}

impl FfiEngine {
    /// Inicia o motor a partir de um `CoreConfig`.
    pub fn start(config: CoreConfig) -> Result<Self, FfiError> {
        let running = Arc::new(AtomicBool::new(true));
        let running_clone = Arc::clone(&running);
        let (tx_ready, rx_ready) = std::sync::mpsc::channel();

        // `CoreTask` contém fluxos de áudio e listeners TCP/QUIC do Tokio que exigem
        // um reator ativo e não implementam `Send`. Inicializamos dentro de `local.block_on(&rt, ...)`
        // em uma thread dedicada para isolamento completo.
        std::thread::Builder::new()
            .name("anarchord-core-worker".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = tx_ready.send(Err(FfiError::Start(format!("Falha ao criar runtime worker: {}", e))));
                        running_clone.store(false, Ordering::Relaxed);
                        return;
                    }
                };

                let local = tokio::task::LocalSet::new();
                local.block_on(&rt, async move {
                    let (core, task) = match Core::start(config) {
                        Ok(pair) => pair,
                        Err(e) => {
                            let _ = tx_ready.send(Err(FfiError::Start(e.to_string())));
                            return;
                        }
                    };
                    let port = task.listen_port();
                    let peer_id = task.peer_id().to_string();
                    let (commands, events) = core.split();
                    if tx_ready.send(Ok((commands, events, port, peer_id))).is_err() {
                        return;
                    }

                    task.run().await;
                });
                running_clone.store(false, Ordering::Relaxed);
            })
            .map_err(|e| FfiError::Start(format!("Falha ao iniciar thread do core: {}", e)))?;

        let (commands, events, listen_port, peer_id) = rx_ready
            .recv()
            .map_err(|_| FfiError::Start("Thread de inicialização finalizou prematuramente".into()))??;

        Ok(Self {
            commands,
            events,
            listen_port,
            peer_id,
            running,
        })
    }

    /// Porta local escutada pelo nó P2P (TCP e QUIC).
    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    /// PeerId do nó P2P.
    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    /// Envia um comando tipado para o core.
    pub fn send_command(&self, command: CoreCommand) -> Result<(), FfiError> {
        self.commands
            .send(command)
            .map_err(|_| FfiError::ChannelClosed)
    }

    /// Envia um comando decodificado a partir de uma fatia de bytes brutos na memória.
    /// Tenta deserialização binária rápida (Postcard) primeiro, com fallback para JSON.
    pub fn send_command_bytes(&self, bytes: &[u8]) -> Result<(), FfiError> {
        if bytes.is_empty() {
            return Ok(());
        }
        let command: CoreCommand = postcard::from_bytes(bytes)
            .or_else(|_| serde_json::from_slice(bytes))
            .map_err(|e| FfiError::Codec(format!("Falha ao decodificar comando: {}", e)))?;

        self.send_command(command)
    }

    /// Coleta o próximo evento de forma não-bloqueante (retorna `None` se a fila estiver vazia).
    pub fn poll_event(&mut self) -> Option<CoreEvent> {
        self.events.try_recv().ok()
    }

    /// Aguarda o próximo evento de forma assíncrona.
    pub async fn recv_event(&mut self) -> Option<CoreEvent> {
        self.events.recv().await
    }

    /// Coleta o próximo evento e o serializa em bytes (Postcard binário).
    pub fn poll_event_bytes(&mut self) -> Option<Vec<u8>> {
        let event = self.poll_event()?;
        postcard::to_allocvec(&event).ok()
    }

    /// Separa a ponta de envio de comandos e recepção de eventos para uso idiomático em Rust.
    pub fn split(self) -> (UnboundedSender<CoreCommand>, UnboundedReceiver<CoreEvent>) {
        (self.commands, self.events)
    }

    /// Sinaliza desligamento para o core.
    pub fn stop(&self) {
        let _ = self.commands.send(CoreCommand::Shutdown);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }
}
