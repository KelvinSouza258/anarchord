//! Tela: transmitir (anúncio no tópico do espaço, quadros no tópico da stream), assistir e
//! repassar os quadros para a janela da interface.

use super::{CoreError, CoreEvent, FrameSink, Runtime, ScreenEvent};
use crate::community::{self, Space};
use crate::node::P2PNode;
use crate::screen::{max_width_for_quality, KeyframeGate, ScreenAnnounce, ScreenCaptureEngine, ScreenPacket};
use libp2p::gossipsub::IdentTopic;
use std::collections::HashMap;
use std::sync::mpsc::TrySendError;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Sem anúncio por esse tempo, a stream some da lista
const STREAM_EXPIRY: Duration = Duration::from_secs(6);
const FPS: u32 = 30;

struct Stream {
    nick: String,
    pubkey: String,
    topic: IdentTopic,
    last_seen: Instant,
}

pub(super) struct ScreenState {
    pub(super) engine: Arc<ScreenCaptureEngine>,
    /// Tópico de telas do Lobby (anúncios)
    lobby_topic: IdentTopic,
    /// Tópico dos quadros da minha transmissão
    pub(super) publish_topic: IdentTopic,
    /// Minha transmissão: tópico do anúncio e o anúncio
    pub(super) my_stream: Option<(IdentTopic, ScreenAnnounce)>,
    streams: HashMap<String, Stream>,
    /// Stream assistida, o tópico dela e para onde vão os quadros (None no modo de teste)
    watching: Option<(String, IdentTopic, Option<FrameSink>)>,
    gate: KeyframeGate,
    tx: UnboundedSender<ScreenPacket>,
    pub(super) outgoing: Option<UnboundedReceiver<ScreenPacket>>,
}

impl ScreenState {
    pub(super) fn new(node: &mut P2PNode) -> Self {
        let lobby_topic = IdentTopic::new(community::screen_topic(&Space::Lobby));
        let _ = node.swarm.behaviour_mut().gossipsub.subscribe(&lobby_topic);
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        Self {
            engine: Arc::new(ScreenCaptureEngine::new()),
            publish_topic: lobby_topic.clone(),
            lobby_topic,
            my_stream: None,
            streams: HashMap::new(),
            watching: None,
            gate: KeyframeGate::new(),
            tx,
            outgoing: Some(rx),
        }
    }
}

impl Runtime {
    fn stream_id(&self) -> String {
        format!("screen:{}", &self.my_pubkey()[..8])
    }

    fn prepare_stream(&mut self, space: &Space) -> String {
        let stream_id = self.stream_id();
        self.screen.publish_topic = IdentTopic::new(community::screen_stream_topic(space, &stream_id));
        let announce = ScreenAnnounce { stream_id: stream_id.clone(), sender_pubkey: self.my_pubkey(), sender_name: self.nick.clone(), width: 0, height: 0 };
        self.screen.my_stream = Some((IdentTopic::new(community::screen_topic(space)), announce));
        stream_id
    }

    /// Vídeo sintético no Lobby (bots e testes)
    pub(super) fn start_synthetic_video(&mut self) {
        if !self.config.synth_video {
            return;
        }
        let stream_id = self.prepare_stream(&Space::Lobby);
        let tx = self.screen.tx.clone();
        self.screen.engine.start_synthetic_video_stream(stream_id.clone(), self.my_pubkey(), self.nick.clone(), FPS, move |pkt| {
            let _ = tx.send(pkt);
        });
        self.emit(CoreEvent::Screen(ScreenEvent::ShareStarted { stream_id, quality: 360, synthetic: true }));
    }

    pub(super) fn start_screen_share(&mut self, monitor: usize, quality: u32) {
        if self.screen.engine.is_streaming() {
            return self.error(CoreError::AlreadyStreaming);
        }
        let space = self.active.space.clone();
        let stream_id = self.prepare_stream(&space);
        let tx = self.screen.tx.clone();
        self.screen.engine.start_capture(stream_id.clone(), self.my_pubkey(), self.nick.clone(), monitor, FPS, max_width_for_quality(quality), move |pkt| {
            let _ = tx.send(pkt);
        });
        self.emit(CoreEvent::Screen(ScreenEvent::ShareStarted { stream_id, quality, synthetic: false }));
    }

    pub(super) fn stop_screen_share(&mut self) {
        if !self.screen.engine.is_streaming() {
            return self.error(CoreError::NotStreaming);
        }
        self.screen.engine.stop_capture();
        self.screen.my_stream = None;
        self.emit(CoreEvent::Screen(ScreenEvent::ShareStopped));
    }

    /// Quadro capturado: publica no tópico da stream (só quem assiste recebe)
    pub(super) fn broadcast_screen(&mut self, packet: ScreenPacket) {
        if let Some((_, announce)) = self.screen.my_stream.as_mut() {
            announce.width = packet.width;
            announce.height = packet.height;
        }
        let topic = self.screen.publish_topic.clone();
        if self.publish_content(&topic, crate::wire::encode(&packet)).is_ok() && packet.frame_seq % 60 == 0 {
            self.emit(CoreEvent::Screen(ScreenEvent::FrameSent { seq: packet.frame_seq, bytes: packet.video_data.len() }));
        }
    }

    /// A cada 2 s: anuncia a minha transmissão e expira streams que pararam de anunciar
    pub(super) fn screen_tick(&mut self) {
        if let Some((topic, announce)) = self.screen.my_stream.clone() {
            let _ = self.publish_content(&topic, crate::wire::encode(&announce));
        }
        self.screen.streams.retain(|_, s| s.last_seen.elapsed() < STREAM_EXPIRY);
    }

    pub(super) fn on_screen_announce(&mut self, announce: ScreenAnnounce, topic: &str) {
        if announce.sender_pubkey == self.my_pubkey() {
            return;
        }
        let stream_topic = IdentTopic::new(format!("{}/{}", topic, announce.stream_id));
        let is_new = !self.screen.streams.contains_key(&announce.stream_id);
        self.screen.streams.insert(
            announce.stream_id.clone(),
            Stream { nick: announce.sender_name.clone(), pubkey: announce.sender_pubkey.clone(), topic: stream_topic.clone(), last_seen: Instant::now() },
        );
        if is_new {
            self.emit(CoreEvent::Screen(ScreenEvent::StreamAvailable { stream_id: announce.stream_id.clone(), nick: announce.sender_name.clone() }));
            // Modo de teste: assiste tudo, para validar o vídeo de ponta a ponta
            if self.config.test_mode && self.screen.watching.is_none() {
                let _ = self.node.swarm.behaviour_mut().gossipsub.subscribe(&stream_topic);
                self.screen.watching = Some((announce.stream_id, stream_topic, None));
            }
        }
    }

    pub(super) fn watch_screen(&mut self, query: &str, sink: FrameSink) {
        let found = self
            .screen
            .streams
            .iter()
            .find(|(id, s)| s.nick.eq_ignore_ascii_case(query) || id.starts_with(query) || s.pubkey.starts_with(query))
            .map(|(id, s)| (id.clone(), s.nick.clone(), s.topic.clone()));
        let Some((stream_id, nick, topic)) = found else { return self.error(CoreError::NoStream(query.to_string())) };
        if let Some((_, previous, _)) = self.screen.watching.take() {
            let _ = self.node.swarm.behaviour_mut().gossipsub.unsubscribe(&previous);
        }
        // Só agora passa a receber os quadros dessa stream
        let _ = self.node.swarm.behaviour_mut().gossipsub.subscribe(&topic);
        self.screen.watching = Some((stream_id.clone(), topic, Some(sink)));
        self.screen.gate = KeyframeGate::new();
        self.emit(CoreEvent::Screen(ScreenEvent::Watching { stream_id, nick }));
    }

    pub(super) fn on_screen_frame(&mut self, packet: ScreenPacket) {
        let Some((stream_id, topic, sink)) = &self.screen.watching else { return };
        if *stream_id != packet.stream_id {
            return;
        }
        if packet.frame_seq % 60 == 0 {
            self.emit(CoreEvent::Screen(ScreenEvent::FrameReceived {
                nick: packet.sender_name.clone(),
                seq: packet.frame_seq,
                bytes: packet.video_data.len(),
                width: packet.width,
                height: packet.height,
            }));
        }
        let Some(sink) = sink else { return };
        // Fila cheia descarta o quadro sem travar a rede; o gate segura os P-frames seguintes
        // até o próximo keyframe para não corromper a imagem
        let (codec, data) = (packet.codec, packet.video_data);
        let mut closed = false;
        self.screen.gate.forward(packet.is_keyframe, || match sink.try_send((codec, data)) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => false,
            Err(TrySendError::Disconnected(_)) => {
                closed = true;
                false
            }
        });
        if closed {
            // A janela fechou: sai da transmissão
            let topic = topic.clone();
            let _ = self.node.swarm.behaviour_mut().gossipsub.unsubscribe(&topic);
            self.screen.watching = None;
            self.emit(CoreEvent::Screen(ScreenEvent::WatchEnded));
        }
    }

    #[allow(dead_code)]
    pub(super) fn lobby_screen_topic(&self) -> &IdentTopic {
        &self.screen.lobby_topic
    }
}
