//! Voz: microfone e alto-falante, sala de voz, falantes e o sintetizador de teste.

use super::{CoreError, CoreEvent, Runtime, VoiceEvent};
use crate::community::{self, ChannelType};
use crate::voice::{AudioCodec, JitterBuffer, VoiceEngine, VoicePacket};
use libp2p::gossipsub::IdentTopic;
use opus1::{Application, Channels, OpusDecoder, OpusEncoder, SampleRate};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// Silêncio a partir do qual um par deixa de aparecer falando
const SPEAKING_TIMEOUT: Duration = Duration::from_millis(600);

#[derive(Default)]
pub(super) struct VoiceState {
    engine: Option<VoiceEngine>,
    pub(super) channel: Option<String>,
    pub(super) topic: Option<IdentTopic>,
    /// Nicks presentes na sala de voz (inclui o próprio)
    peers: HashSet<String>,
    /// pubkey -> (nick, último pacote)
    speakers: HashMap<String, (String, Instant)>,
    jitter: HashMap<String, JitterBuffer>,
    decoders: HashMap<String, OpusDecoder>,
    /// Pacotes do microfone (ou do sintetizador) a publicar
    pub(super) outgoing: Option<UnboundedReceiver<VoicePacket>>,
    sender: Option<UnboundedSender<VoicePacket>>,
}

impl Runtime {
    pub(super) fn start_voice(&mut self) {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.voice.outgoing = Some(rx);
        self.voice.sender = Some(tx.clone());
        let seq = Arc::new(AtomicU64::new(1));

        if self.config.audio {
            match VoiceEngine::start() {
                Ok((engine, mic)) => {
                    spawn_microphone(mic, engine.is_muted_handle(), tx.clone(), Arc::clone(&seq), self.my_pubkey(), self.nick.clone());
                    self.voice.engine = Some(engine);
                    self.emit(CoreEvent::Voice(VoiceEvent::AudioReady));
                }
                Err(e) => self.emit(CoreEvent::Network(super::NetworkEvent::AudioUnavailable(e.to_string()))),
            }
        }
        if self.config.synth_audio {
            spawn_synth(tx, seq, self.my_pubkey(), self.nick.clone());
            self.emit(CoreEvent::Voice(VoiceEvent::SynthStarted));
        }
        if let Some(channel) = self.config.auto_voice.clone() {
            self.join_voice(channel);
        }
    }

    pub(super) fn join_voice(&mut self, channel: String) {
        if let Some(server) = self.active.server_id().and_then(|id| self.servers.get(id)) {
            if !server.has_channel(&channel, ChannelType::Voice) {
                return self.error(CoreError::NoSuchChannel { name: channel, voice: true });
            }
        }
        if let Some(previous) = self.voice.topic.take() {
            let _ = self.node.swarm.behaviour_mut().gossipsub.unsubscribe(&previous);
        }
        self.voice.peers.clear();
        self.voice.peers.insert(self.nick.clone());
        let topic = IdentTopic::new(community::voice_topic(&self.active.space, &channel));
        if let Err(e) = self.node.swarm.behaviour_mut().gossipsub.subscribe(&topic) {
            return self.error(CoreError::Network(format!("{:?}", e)));
        }
        self.voice.channel = Some(channel.clone());
        self.voice.topic = Some(topic);
        self.emit(CoreEvent::Voice(VoiceEvent::Joined(channel.clone())));
        self.emit_voice_members();
        // Todo canal de voz também é um canal de texto com o mesmo nome (no Lobby e em servidores):
        // sincroniza o canal de texto ativo ao entrar na sala de voz.
        if self.active.channel != channel {
            let space = self.active.space.clone();
            self.enter_channel(space, channel);
        }
    }

    pub(super) fn leave_voice(&mut self) {
        let Some(previous) = self.voice.topic.take() else { return self.error(CoreError::NotInVoice) };
        let _ = self.node.swarm.behaviour_mut().gossipsub.unsubscribe(&previous);
        let name = self.voice.channel.take().unwrap_or_default();
        self.voice.peers.clear();
        self.emit(CoreEvent::Voice(VoiceEvent::Left(name.clone())));
        self.emit_voice_members();
        // Se o chat ativo ainda era o canal da sala de voz que acabamos de sair,
        // voltamos para o canal de texto padrão do espaço atual.
        if self.active.channel == name {
            let space = self.active.space.clone();
            let fallback = match &space {
                crate::community::Space::Lobby => "geral".to_string(),
                crate::community::Space::Server(id) => self.default_channel(id),
            };
            if fallback != name {
                self.enter_channel(space, fallback);
            }
        }
    }

    pub(super) fn toggle_mute(&mut self) {
        if let Some(engine) = &self.voice.engine {
            let muted = engine.toggle_mute();
            self.emit(CoreEvent::Voice(VoiceEvent::Muted(muted)));
        }
    }

    fn emit_voice_members(&self) {
        let mut members: Vec<String> = self.voice.peers.iter().cloned().collect();
        members.sort();
        self.emit(CoreEvent::Voice(VoiceEvent::Members(members)));
    }

    /// Pacote do microfone: vai para a sala de voz atual
    pub(super) fn broadcast_voice(&mut self, mut packet: VoicePacket) {
        let (Some(topic), Some(channel)) = (self.voice.topic.clone(), self.voice.channel.clone()) else { return };
        packet.channel_id = channel;
        if let Err(e) = self.publish_content(&topic, crate::wire::encode(&packet)) {
            tracing::debug!("Erro ao publicar pacote de voz: {:?}", e);
        }
    }

    /// Pacote de outro par: presença na sala, quem está falando e reprodução
    pub(super) fn on_voice_packet(&mut self, packet: VoicePacket) {
        if packet.sender_pubkey == self.my_pubkey() {
            return;
        }
        if self.voice.peers.insert(packet.sender_name.clone()) {
            self.emit_voice_members();
        }
        let now = Instant::now();
        match self.voice.speakers.get_mut(&packet.sender_pubkey) {
            Some(speaker) => speaker.1 = now,
            None => {
                self.voice.speakers.insert(packet.sender_pubkey.clone(), (packet.sender_name.clone(), now));
                self.emit(CoreEvent::Voice(VoiceEvent::Speaking { nick: packet.sender_name.clone(), speaking: true }));
            }
        }

        let sender = packet.sender_pubkey.clone();
        let buffer = self.voice.jitter.entry(sender.clone()).or_insert_with(|| JitterBuffer::new(10));
        buffer.push(packet);
        let Some(ready) = buffer.pop_next() else { return };
        let Some(engine) = &self.voice.engine else { return };
        let samples = match ready.codec {
            AudioCodec::Opus => {
                let decoder = self
                    .voice
                    .decoders
                    .entry(sender)
                    .or_insert_with(|| OpusDecoder::new(SampleRate::Hz48000, Channels::Mono).expect("decoder Opus"));
                ready.to_pcm_samples_opus(decoder).unwrap_or_else(|_| ready.to_pcm_samples())
            }
            AudioCodec::Pcm16 => ready.to_pcm_samples(),
        };
        engine.play_remote_samples(samples);
    }

    /// Quem parou de falar
    pub(super) fn speaker_tick(&mut self) {
        let now = Instant::now();
        let stopped: Vec<String> = self
            .voice
            .speakers
            .iter()
            .filter(|(_, (_, last))| now.duration_since(*last) > SPEAKING_TIMEOUT)
            .map(|(pk, _)| pk.clone())
            .collect();
        for pubkey in stopped {
            if let Some((nick, _)) = self.voice.speakers.remove(&pubkey) {
                self.emit(CoreEvent::Voice(VoiceEvent::Speaking { nick, speaking: false }));
            }
        }
    }
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64
}

fn packet(seq: &AtomicU64, pubkey: &str, nick: &str, samples: &[f32], encoder: Option<&mut OpusEncoder>) -> VoicePacket {
    let seq = seq.fetch_add(1, Ordering::SeqCst);
    let pcm = || VoicePacket::from_pcm_samples("active_voice".into(), pubkey.into(), nick.into(), seq, now_ms(), samples);
    match encoder {
        Some(encoder) => VoicePacket::from_pcm_samples_opus("active_voice".into(), pubkey.into(), nick.into(), seq, now_ms(), samples, encoder)
            .unwrap_or_else(|_| pcm()),
        None => pcm(),
    }
}

/// Microfone -> Opus -> fila de publicação, só quando há fala (VAD) e sem mute
fn spawn_microphone(
    mic: std::sync::mpsc::Receiver<Vec<f32>>,
    muted: Arc<std::sync::atomic::AtomicBool>,
    tx: UnboundedSender<VoicePacket>,
    seq: Arc<AtomicU64>,
    pubkey: String,
    nick: String,
) {
    std::thread::spawn(move || {
        let mut encoder = OpusEncoder::new(SampleRate::Hz48000, Channels::Mono, Application::Voip).ok();
        while let Ok(samples) = mic.recv() {
            if muted.load(Ordering::Relaxed) || crate::calculate_vad_energy(&samples) < 8 {
                continue;
            }
            if tx.send(packet(&seq, &pubkey, &nick, &samples, encoder.as_mut())).is_err() {
                break;
            }
        }
    });
}

/// Melodia chiptune em Opus, para bots e testes de voz
fn spawn_synth(tx: UnboundedSender<VoicePacket>, seq: Arc<AtomicU64>, pubkey: String, nick: String) {
    std::thread::spawn(move || {
        let mut encoder = OpusEncoder::new(SampleRate::Hz48000, Channels::Mono, Application::Voip).expect("encoder Opus");
        let sample_rate = crate::SAMPLE_RATE as f32;
        let frame_size = crate::FRAME_SIZE;
        const REST: f32 = 0.0;
        const C4: f32 = 261.63;
        const E4: f32 = 329.63;
        const F4: f32 = 349.23;
        const G4: f32 = 392.00;
        const A4: f32 = 440.00;
        const B4: f32 = 493.88;
        const C5: f32 = 523.25;
        const D5: f32 = 587.33;
        const E5: f32 = 659.25;
        const G5: f32 = 783.99;
        // (melodia, baixo, duração em quadros de 20 ms)
        let score: [(f32, f32, u32); 43] = [
            (E5, C4, 6), (REST, REST, 2), (E5, C4, 6), (REST, REST, 4), (E5, C4, 6), (REST, REST, 4),
            (C5, G4, 6), (REST, REST, 2), (E5, C4, 6), (REST, REST, 4), (G5, G4, 12), (REST, REST, 6),
            (G4, G4, 12), (REST, REST, 8),
            (E4, C4, 8), (B4, G4, 4), (C5, E4, 4), (D5, G4, 8), (C5, E4, 4), (B4, G4, 4),
            (A4, F4, 8), (A4, F4, 4), (C5, A4, 4), (E5, C4, 8), (D5, G4, 4), (C5, E4, 4),
            (B4, G4, 10), (C5, E4, 4), (D5, G4, 8), (E5, C4, 8),
            (C5, A4, 8), (A4, F4, 8), (A4, F4, 10), (REST, REST, 6),
            (C4, C4, 4), (E4, C4, 4), (G4, E4, 4), (C5, G4, 4), (E5, C5, 6), (REST, REST, 4),
            (D5, B4, 6), (C5, C4, 12), (REST, REST, 10),
        ];
        let tau = 2.0 * std::f32::consts::PI;
        let (mut note, mut frames_left) = (0usize, score[0].2);
        let (mut lead_phase, mut bass_phase) = (0f32, 0f32);
        loop {
            let started = Instant::now();
            let (lead, bass, _) = score[note];
            let lead_step = tau * lead / sample_rate;
            let bass_step = tau * bass / sample_rate;
            let samples: Vec<f32> = (0..frame_size)
                .map(|_| {
                    // Ondas quadradas: melodia com 50% de duty-cycle, baixo com 25%
                    let l = if lead > 0.0 { if lead_phase < std::f32::consts::PI { 0.25 } else { -0.25 } } else { 0.0 };
                    let b = if bass > 0.0 { if bass_phase < std::f32::consts::PI * 0.5 { 0.15 } else { -0.15 } } else { 0.0 };
                    lead_phase = (lead_phase + lead_step) % tau;
                    bass_phase = (bass_phase + bass_step) % tau;
                    l + b
                })
                .collect();
            frames_left -= 1;
            if frames_left == 0 {
                note = (note + 1) % score.len();
                frames_left = score[note].2;
            }
            if tx.send(packet(&seq, &pubkey, &nick, &samples, Some(&mut encoder))).is_err() {
                break;
            }
            if let Some(rest) = Duration::from_millis(20).checked_sub(started.elapsed()) {
                std::thread::sleep(rest);
            }
        }
    });
}
