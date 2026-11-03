//! Ponte entre o motor do enxame de arquivos e a rede.

use super::{CoreError, CoreEvent, Runtime};
use crate::api::pubkey_hex_from_peer_id;
use crate::community;
use crate::files::{self as swarm_files, FileAction, FileEngine, FileEvent, FileKey, FileRequest, Manifest, ShareTarget};
use crate::identity::UserIdentity;
use libp2p::request_response::{self, OutboundRequestId};
use libp2p::PeerId;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Manifesto montado em segundo plano, pronto para compartilhar
pub(super) struct ManifestJob {
    manifest: std::io::Result<Manifest>,
    path: PathBuf,
    key: Option<FileKey>,
    target: ShareTarget,
}

pub(super) struct FilesState {
    pub(super) engine: FileEngine,
    requests: HashMap<OutboundRequestId, (PeerId, FileRequest)>,
    tx: UnboundedSender<ManifestJob>,
    pub(super) manifests: Option<UnboundedReceiver<ManifestJob>>,
}

impl FilesState {
    pub(super) fn new(identity: &UserIdentity, download_dir: PathBuf) -> Self {
        // Parciais separados por identidade: vários nós na mesma máquina não se misturam
        let partial_dir = download_dir.join(".parcial").join(&identity.public_key_hex()[..8]);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Self { engine: FileEngine::new(partial_dir, download_dir), requests: HashMap::new(), tx, manifests: Some(rx) }
    }
}

impl Runtime {
    pub(super) fn resume_files(&mut self) {
        let actions = self.files.engine.resume(Instant::now());
        self.apply_file_actions(actions);
    }

    pub(super) fn share_file(&mut self, path: PathBuf) {
        // Em servidor, os pedaços vão cifrados com uma chave que só viaja na oferta (MLS)
        let key = match self.active.server_id() {
            Some(id) if !self.mls.has_group(id) => return self.error(CoreError::NoGroupKey),
            Some(_) => Some(FileKey::generate()),
            None => None,
        };
        let target = ShareTarget::Topic(self.active.topic.hash().into_string());
        self.build_manifest(path, key, target);
    }

    pub(super) fn send_file(&mut self, to: &str, path: PathBuf) {
        match self.find_peer(to) {
            Some(peer) => self.build_manifest(path, None, ShareTarget::Peer(peer)),
            None => self.error(CoreError::PeerNotFound(to.to_string())),
        }
    }

    /// Lê o arquivo e monta o manifesto numa thread de bloqueio, sem travar o loop
    fn build_manifest(&mut self, path: PathBuf, key: Option<FileKey>, target: ShareTarget) {
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default().to_string();
        self.emit(CoreEvent::FilePreparing { name });
        let (tx, identity) = (self.files.tx.clone(), self.identity.clone());
        tokio::task::spawn_blocking(move || {
            let manifest = Manifest::from_file(&path, &identity, key.as_ref(), super::now_secs());
            let _ = tx.send(ManifestJob { manifest, path, key, target });
        });
    }

    pub(super) fn manifest_ready(&mut self, job: ManifestJob) {
        match job.manifest {
            Ok(manifest) => {
                let nick = self.nick.clone();
                let (_, actions) = self.files.engine.share(manifest, job.path, job.key, job.target, &nick);
                self.apply_file_actions(actions);
            }
            Err(e) => self.error(CoreError::Io { context: job.path.display().to_string(), message: e.to_string() }),
        }
    }

    pub(super) fn get_file(&mut self, query: &str) {
        match self.files.engine.get(query, Instant::now()) {
            Ok(actions) => self.apply_file_actions(actions),
            Err(e) => self.error(CoreError::File(e)),
        }
    }

    pub(super) fn reject_file(&mut self, query: &str) {
        match self.files.engine.dismiss(query) {
            Ok(name) => self.emit(CoreEvent::File(FileEvent::Dismissed { name })),
            Err(e) => self.error(CoreError::File(e)),
        }
    }

    pub(super) fn unshare_file(&mut self, query: &str) {
        match self.files.engine.unshare(query) {
            Ok(name) => self.emit(CoreEvent::File(FileEvent::Unshared { name })),
            Err(e) => self.error(CoreError::File(e)),
        }
    }

    pub(super) fn list_files(&mut self) {
        self.emit(CoreEvent::Files(self.files.engine.list(Instant::now())));
    }

    pub(super) fn files_tick(&mut self) {
        let actions = self.files.engine.tick(Instant::now());
        self.apply_file_actions(actions);
    }

    /// Pedidos de outros pares e respostas aos nossos pelo protocolo de arquivos
    pub(super) fn on_files_event(&mut self, event: request_response::Event<FileRequest, swarm_files::FileResponse>) {
        let now = Instant::now();
        let actions = match event {
            request_response::Event::Message { peer, message, .. } => match message {
                request_response::Message::Request { request, channel, .. } => {
                    // Arquivo de servidor: só responde a membros do grupo cifrado
                    let requester = pubkey_hex_from_peer_id(&peer);
                    let mls = &self.mls;
                    let allow = |topic: &str| match community::parse_server_content_topic(topic) {
                        Some(server_id) => requester.as_ref().is_some_and(|pk| mls.members(server_id).contains(pk)),
                        None => true,
                    };
                    let (response, actions) = self.files.engine.handle_request(peer, request, &allow, now);
                    let _ = self.node.swarm.behaviour_mut().files.send_response(channel, response);
                    actions
                }
                request_response::Message::Response { request_id, response } => match self.files.requests.remove(&request_id) {
                    Some((peer, request)) => self.files.engine.on_response(peer, request, response, now),
                    None => Vec::new(),
                },
            },
            request_response::Event::OutboundFailure { request_id, error, .. } => match self.files.requests.remove(&request_id) {
                Some((peer, request)) => {
                    tracing::debug!("Pedido de arquivo para {} falhou: {}", peer, error);
                    self.files.engine.on_failure(peer, request, now)
                }
                None => Vec::new(),
            },
            _ => Vec::new(),
        };
        self.apply_file_actions(actions);
    }

    /// Executa o que o motor do enxame pediu
    pub(super) fn apply_file_actions(&mut self, actions: Vec<FileAction>) {
        let mut queue: std::collections::VecDeque<FileAction> = actions.into();
        while let Some(action) = queue.pop_front() {
            match action {
                FileAction::Request { peer, request } => {
                    let id = self.node.swarm.behaviour_mut().files.send_request(&peer, request.clone());
                    self.files.requests.insert(id, (peer, request));
                }
                FileAction::Publish { topic, message } => {
                    if self.publish_content(&libp2p::gossipsub::IdentTopic::new(topic), crate::wire::encode(&message)).is_err() {
                        tracing::debug!("Mensagem do enxame não publicada (sem pares no tópico ou sem chave do grupo)");
                    }
                }
                FileAction::Provide(cid) => self.node.dht_provide(swarm_files::dht_key(&cid)),
                FileAction::FindProviders(cid) => self.node.dht_find(swarm_files::dht_key(&cid)),
                FileAction::Event(event) => {
                    // Modo de teste: baixa tudo o que for oferecido
                    if let (true, FileEvent::Offered { cid, .. }) = (self.config.test_mode, &event) {
                        if let Ok(more) = self.files.engine.get(&cid.short(), Instant::now()) {
                            queue.extend(more);
                        }
                    }
                    self.emit(CoreEvent::File(event));
                }
            }
        }
    }
}
