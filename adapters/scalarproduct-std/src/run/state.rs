//! Real per-session composite native effects; all bytes retain original owners.
use super::{Control, NativeEntropy};
use crate::backend::{
    Action, Completion, Computation, EffectId, InputId, IntersectionId, PeerKind, PeerSource,
};
use crate::{Error, Limits, Role, SessionReport, buffer};
use gnunet_cadet_host as cadet;
use gnunet_client_host::EndpointSource;
use gnunet_service_runtime::{
    clock::Deadline,
    framing::{Class, Framed, OwnedFrame, ReadStep},
};
use gnunet_seti_client_host as seti;
use gnunet_types::Error as Fault;
use gnunet_wire::official::{scalarproduct::PeerMessage, seti::Response as SetResponse};
use std::{
    future::Future,
    pin::Pin,
    rc::Rc,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

struct Setup<'i> {
    id: EffectId<'i>,
    intersection: IntersectionId<'i>,
    peer: [u8; 32],
    app: [u8; 64],
    listener: bool,
    cursor: usize,
    add: Option<seti::WriteId<'i>>,
    populated: bool,
    started: bool,
}
struct NativeWrite<'i> {
    effect: Option<EffectId<'i>>,
    transmit: cadet::Transmit<'i>,
    bytes: usize,
    hard: Instant,
}
struct Packet<'i> {
    received: cadet::Received<'i>,
    source: PeerSource,
    at: usize,
    processing: Option<(InputId<'i>, u64, usize)>,
}
pub(super) struct State<'i, 'slots> {
    core: Computation<'i>,
    cadet: cadet::Client<'i, 'slots>,
    io: Framed<u64>,
    set: Option<seti::Client<'i>>,
    listener: Option<seti::Client<'i>>,
    set_brand: Option<&'i mut seti::Instance>,
    listener_brand: Option<&'i mut seti::Instance>,
    set_source: Option<EndpointSource>,
    listener_source: Option<EndpointSource>,
    setup: Option<Setup<'i>>,
    intersection: Option<IntersectionId<'i>>,
    operation: Option<seti::Operation<'i>>,
    incoming: Option<seti::Incoming<'i>>,
    port: Option<cadet::Port<'i>>,
    channel: Option<cadet::Channel<'i>>,
    reject: Option<cadet::Channel<'i>>,
    write: Option<NativeWrite<'i>>,
    packet: Option<Packet<'i>>,
    next_input: Option<u64>,
    output: Option<(EffectId<'i>, usize, Instant)>,
    set_hard: Option<Instant>,
    listener_hard: Option<Instant>,
    set_partial: Option<Instant>,
    listener_partial: Option<Instant>,
    cadet_hard: Option<Instant>,
    partial: Option<Instant>,
    entropy: NativeEntropy,
    limits: Limits,
    canonical_until: u64,
    native_until: Instant,
    deadline: Deadline,
    timer: Pin<Box<Sleep>>,
    control: Rc<Control>,
    cadet_active: bool,
    closed_peer: Option<PeerSource>,
    session_written: bool,
    setup_exposed: bool,
    set_created_written: bool,
    listen_written: bool,
    cpu: bool,
    matched: usize,
    sent: usize,
    class: usize,
    set_first: bool,
    report: SessionReport,
    finished: bool,
    dependency_undrained: bool,
}
fn set_poll<'i>(
    client: &mut seti::Client<'i>,
    cx: &mut Context<'_>,
) -> Poll<Result<seti::Step<'i>, seti::Error>> {
    let mut future = std::pin::pin!(client.drive(None));
    future.as_mut().poll(cx)
}
fn transient(error: &cadet::Error) -> bool {
    matches!(
        error,
        cadet::Error::Protocol(Fault::WouldBlock | Fault::NotReady | Fault::Capacity)
    )
}
impl<'i, 'slots> State<'i, 'slots> {
    #[expect(
        clippy::too_many_arguments,
        reason = "all original native brands, sources and immutable bounds are explicit"
    )]
    pub fn new(
        core: Computation<'i>,
        cadet: cadet::Client<'i, 'slots>,
        io: Framed<u64>,
        set_source: EndpointSource,
        listener_source: EndpointSource,
        set_brand: &'i mut seti::Instance,
        listener_brand: &'i mut seti::Instance,
        entropy: NativeEntropy,
        limits: Limits,
        canonical_until: u64,
        native_until: Instant,
        control: Rc<Control>,
        role: Role,
    ) -> Result<Self, Error> {
        let deadline = Deadline::at(
            cadet.clock(),
            gnunet_types::AbsoluteTime::from_micros(canonical_until),
        )?;
        Ok(Self {
            core,
            cadet,
            io,
            set: None,
            listener: None,
            set_brand: Some(set_brand),
            listener_brand: Some(listener_brand),
            set_source: Some(set_source),
            listener_source: Some(listener_source),
            setup: None,
            intersection: None,
            operation: None,
            incoming: None,
            port: None,
            channel: None,
            reject: None,
            write: None,
            packet: None,
            next_input: Some(1),
            output: None,
            set_hard: None,
            listener_hard: None,
            set_partial: None,
            listener_partial: None,
            cadet_hard: None,
            partial: None,
            entropy,
            limits,
            canonical_until,
            native_until,
            deadline,
            timer: Box::pin(tokio::time::sleep_until(native_until)),
            control,
            cadet_active: false,
            closed_peer: None,
            session_written: false,
            setup_exposed: false,
            set_created_written: false,
            listen_written: false,
            cpu: false,
            matched: 0,
            sent: 0,
            class: 0,
            set_first: false,
            report: SessionReport {
                role: Some(role),
                ..SessionReport::default()
            },
            finished: false,
            dependency_undrained: false,
        })
    }
    fn hard(&self) -> Result<Instant, Error> {
        Ok(Instant::now()
            .checked_add(self.limits.retirement_grace)
            .ok_or(Fault::Overflow)?)
    }
    fn until(&self) -> Result<u64, Error> {
        let now = self.cadet.clock().sample()?.now.as_micros();
        let grace =
            u64::try_from(self.limits.retirement_grace.as_micros()).map_err(|_| Fault::Overflow)?;
        Ok(now
            .checked_add(grace)
            .ok_or(Fault::Overflow)?
            .min(self.canonical_until))
    }
    fn source(&self, channel: cadet::Channel<'i>) -> Result<PeerSource, Error> {
        let info = self.cadet.channel_info(channel)?;
        Ok(PeerSource {
            epoch: channel.epoch().value(),
            channel: channel.value(),
            peer: info.peer,
        })
    }
    fn core_error(&self, cause: Fault) -> Error {
        self.core
            .paillier_error()
            .filter(|error| crate::backend::classify_paillier(*error) == cause)
            .map_or_else(|| Error::Protocol(cause), Error::Paillier)
    }
    fn admit(&mut self, id: EffectId<'i>) -> Result<(), Error> {
        if !self.core.effect().ok_or(Fault::NotReady)?.is_admitted() {
            self.core
                .admit_effect(id)
                .map_err(|cause| self.core_error(cause))?;
        }
        Ok(())
    }
    fn complete(&mut self, id: EffectId<'i>, completion: Completion) -> Result<(), Error> {
        match completion {
            Completion::Written => self.report.written = self.report.written.saturating_add(1),
            Completion::Lost(_) => self.report.lost = self.report.lost.saturating_add(1),
            Completion::Unsent(_) => self.report.unsent = self.report.unsent.saturating_add(1),
            _ => {}
        }
        self.core
            .complete_effect(id, completion)
            .map_err(|cause| self.core_error(cause))?;
        Ok(())
    }
    fn start_setup(
        &mut self,
        id: EffectId<'i>,
        intersection: IntersectionId<'i>,
        peer: [u8; 32],
        app: [u8; 64],
        listener: bool,
    ) -> Result<bool, Error> {
        self.admit(id)?;
        if self.setup.is_some() {
            return Ok(false);
        }
        self.setup_exposed = false;
        self.set_created_written = false;
        self.listen_written = false;
        let until = self.until()?;
        self.set = Some(seti::Client::new_set(
            self.set_brand.take().ok_or(Fault::Stale)?,
            self.set_source.take().ok_or(Fault::Stale)?,
            self.limits.seti,
            until,
        )?);
        self.set_hard = Some(self.hard()?);
        if listener {
            self.listener = Some(seti::Client::new_listener(
                self.listener_brand.take().ok_or(Fault::Stale)?,
                self.listener_source.take().ok_or(Fault::Stale)?,
                self.limits.seti,
                app,
                self.canonical_until,
            )?);
            self.listener_hard = Some(self.hard()?);
        }
        self.intersection = Some(intersection);
        self.setup = Some(Setup {
            id,
            intersection,
            peer,
            app,
            listener,
            cursor: 0,
            add: None,
            populated: false,
            started: false,
        });
        Ok(true)
    }
    fn populate(&mut self) -> Result<bool, Error> {
        let Some(setup) = self.setup.as_ref() else {
            return Ok(false);
        };
        if !self.set.as_ref().is_some_and(seti::Client::initialized) || setup.add.is_some() {
            return Ok(false);
        }
        let id = setup.id;
        let intersection = setup.intersection;
        let cursor = setup.cursor;
        let listener = setup.listener;
        let populated = setup.populated;
        let peer = setup.peer;
        let app = setup.app;
        if !populated {
            if let Some(key) = self.core.intersection_key(intersection, cursor)?.copied() {
                let until = self.until()?;
                let write = self.set.as_mut().ok_or(Fault::Stale)?.add(0, &key, until)?;
                self.setup.as_mut().ok_or(Fault::Stale)?.add = Some(write);
                self.set_hard = Some(self.hard()?);
                return Ok(true);
            }
            self.setup.as_mut().ok_or(Fault::Stale)?.populated = true;
            self.matched = cursor;
            return Ok(true);
        }
        if listener {
            if self
                .listener
                .as_ref()
                .is_some_and(seti::Client::initialized)
            {
                self.setup = None;
                self.complete(id, Completion::Written)?;
                return Ok(true);
            }
        } else if !self.setup.as_ref().ok_or(Fault::Stale)?.started {
            let operation = self.set.as_mut().ok_or(Fault::Stale)?.evaluate(
                peer,
                app,
                false,
                None,
                self.canonical_until,
            )?;
            self.operation = Some(operation);
            self.setup.as_mut().ok_or(Fault::Stale)?.started = true;
            self.set_hard = Some(self.hard()?);
            return Ok(true);
        }
        Ok(false)
    }
    fn accept_incoming(&mut self) -> Result<bool, Error> {
        if !self.session_written
            || self.operation.is_some()
            || self.setup.is_some()
            || self.incoming.is_none()
        {
            return Ok(false);
        }
        let incoming = self.incoming.as_mut().ok_or(Fault::Stale)?;
        let peer = match incoming.request()? {
            SetResponse::Request { peer, .. } => peer,
            _ => return Err(Fault::Malformed.into()),
        };
        if self
            .core
            .peer_source()
            .is_none_or(|source| source.peer != peer)
        {
            return Err(Fault::Authentication.into());
        }
        let operation =
            self.set
                .as_mut()
                .ok_or(Fault::Stale)?
                .accept(incoming, false, self.canonical_until)?;
        self.operation = Some(operation);
        self.incoming = None;
        self.set_hard = Some(self.hard()?);
        Ok(true)
    }
    fn actions(&mut self) -> Result<bool, Error> {
        self.core.pump().map_err(|cause| self.core_error(cause))?;
        if self.populate()? || self.accept_incoming()? {
            return Ok(true);
        }
        let Some(effect) = self.core.effect() else {
            return Ok(false);
        };
        let id = effect.id;
        if let Some(failure) = self.core.outcome().failure
            && !effect.is_admitted()
            && !matches!(
                effect.action,
                Action::ClientResult { .. }
                    | Action::CloseIntersection { .. }
                    | Action::ClosePeer { .. }
                    | Action::ClosePort { .. }
            )
        {
            self.admit(id)?;
            self.complete(id, Completion::Unsent(failure.cause))?;
            return Ok(true);
        }
        if self.closed_peer.is_some()
            && matches!(
                effect.action,
                Action::ListenIntersection { .. }
                    | Action::StartIntersection { .. }
                    | Action::OpenPort { .. }
                    | Action::Connect { .. }
                    | Action::PeerSend { .. }
            )
        {
            return Err(Fault::Closed.into());
        }
        match &effect.action {
            Action::ListenIntersection {
                id: intersection,
                peer,
                app,
            } => {
                let (intersection, peer, app) = (*intersection, *peer, *app);
                self.start_setup(id, intersection, peer, app, true)
            }
            Action::StartIntersection {
                id: intersection,
                peer,
                app,
            } => {
                let (intersection, peer, app) = (*intersection, *peer, *app);
                self.start_setup(id, intersection, peer, app, false)
            }
            Action::OpenPort { port } => {
                let hash = *port;
                self.admit(id)?;
                let activated = !self.cadet_active;
                self.cadet_active = true;
                self.cadet_hard.get_or_insert(self.hard()?);
                if self.write.is_some() || self.cadet.epoch().is_none() {
                    // The peer class may already have run this turn. Its first
                    // activation needs another poll to start the original MQ.
                    return Ok(activated);
                }
                match self.cadet.listen(hash) {
                    Ok(port) => {
                        let transmit = self.cadet.pending_transmit().ok_or(Fault::NotReady)?;
                        self.port = Some(port);
                        self.write = Some(NativeWrite {
                            effect: Some(id),
                            transmit,
                            bytes: 0,
                            hard: self.hard()?,
                        });
                        Ok(true)
                    }
                    Err(error) if transient(&error) => Ok(false),
                    Err(error) => Err(error.into()),
                }
            }
            Action::Connect { peer, port } => {
                let (peer, port) = (*peer, *port);
                self.admit(id)?;
                let activated = !self.cadet_active;
                self.cadet_active = true;
                self.cadet_hard.get_or_insert(self.hard()?);
                if self.write.is_some() || self.cadet.epoch().is_none() {
                    // The peer class may already have run this turn. Its first
                    // activation needs another poll to start the original MQ.
                    return Ok(activated);
                }
                match self.cadet.open(peer, port) {
                    Ok(channel) => {
                        let source = self.source(channel)?;
                        self.core
                            .attach_peer(source)
                            .map_err(|cause| self.core_error(cause))?;
                        let transmit = self.cadet.pending_transmit().ok_or(Fault::NotReady)?;
                        self.channel = Some(channel);
                        self.write = Some(NativeWrite {
                            effect: Some(id),
                            transmit,
                            bytes: 0,
                            hard: self.hard()?,
                        });
                        Ok(true)
                    }
                    Err(error) if transient(&error) => Ok(false),
                    Err(error) => Err(error.into()),
                }
            }
            Action::PeerSend { source, payload } => {
                if self.write.is_some() {
                    return Ok(false);
                }
                let channel = self.channel.ok_or(Fault::Stale)?;
                if *source != self.source(channel)? {
                    return Err(Fault::StaleGeneration.into());
                }
                if self.cadet.channel_info(channel)?.send_credit == 0
                    || self.cadet.pending_transmit().is_some()
                {
                    return Ok(false);
                }
                let mut bytes = buffer(payload.encoded_len()?)?;
                payload.encode(&mut bytes)?;
                self.admit(id)?;
                match self.cadet.send(channel, 0, &bytes) {
                    Ok(transmit) => {
                        self.write = Some(NativeWrite {
                            effect: Some(id),
                            transmit,
                            bytes: 0,
                            hard: self.hard()?,
                        });
                        Ok(true)
                    }
                    Err(error) if transient(&error) => Ok(false),
                    Err(error) => Err(error.into()),
                }
            }
            Action::ReceiveDone {
                source,
                input,
                delivery,
            } => {
                let (source, input, delivery) = (*source, *input, *delivery);
                let packet = self.packet.as_ref().ok_or(Fault::Stale)?;
                if self.core.peer_source() != Some(source)
                    || packet.source != source
                    || (self.closed_peer != Some(source)
                        && (self.channel != Some(packet.received.channel())
                            || self.source(packet.received.channel())? != source))
                {
                    return Err(Fault::StaleGeneration.into());
                }
                let (original, serial, end) = packet.processing.ok_or(Fault::Stale)?;
                let packet_len = packet.received.messages().len();
                if input != original || delivery != serial {
                    return Err(Fault::StaleGeneration.into());
                }
                self.admit(id)?;
                if end < packet_len {
                    let packet = self.packet.as_mut().ok_or(Fault::Stale)?;
                    packet.at = end;
                    packet.processing = None;
                    self.complete(id, Completion::Processed)?;
                    self.report.inner_processed = self.report.inner_processed.saturating_add(1);
                    return Ok(true);
                }
                if self.closed_peer == Some(source) {
                    // Every inner in this original outer packet is now copied.
                    // Only the algorithm's complete-input gate can turn this
                    // physical loss into existing source-independent work.
                    return self.retire_for_local_work(Fault::Closed.into());
                }
                if self.write.is_some() {
                    return Ok(false);
                }
                let delivery = self
                    .packet
                    .as_ref()
                    .ok_or(Fault::Stale)?
                    .received
                    .delivery();
                match self.cadet.receive_done(delivery) {
                    Ok(transmit) => {
                        self.write = Some(NativeWrite {
                            effect: Some(id),
                            transmit,
                            bytes: 0,
                            hard: self.hard()?,
                        });
                        Ok(true)
                    }
                    Err(error) if transient(&error) => Ok(false),
                    Err(error) => Err(error.into()),
                }
            }
            Action::ClientResult { .. } => {
                if self.output.is_some()
                    || self.packet.as_ref().is_some_and(|packet| {
                        packet.processing.is_none() && packet.at < packet.received.messages().len()
                    })
                {
                    return Ok(false);
                }
                let response = effect.action.client_response().ok_or(Fault::Conflict)?;
                let mut bytes = buffer(response.encoded_len()?)?;
                response.encode(&mut bytes)?;
                self.admit(id)?;
                self.io
                    .enqueue_owned(OwnedFrame::new(bytes), 0, Class::Ordinary)
                    .map_err(|failure| failure.reason)?;
                self.output = Some((id, 0, self.hard()?));
                Ok(true)
            }
            Action::CloseIntersection { id: original } => {
                if self
                    .intersection
                    .is_some_and(|current| current != *original)
                {
                    return Err(Fault::StaleGeneration.into());
                }
                self.admit(id)?;
                self.close_seti();
                self.complete(id, Completion::Retired)?;
                Ok(true)
            }
            Action::ClosePeer { source } => {
                if self.core.peer_source() != Some(*source)
                    || self.channel.is_some_and(|channel| {
                        channel.epoch().value() != source.epoch || channel.value() != source.channel
                    })
                {
                    return Err(Fault::StaleGeneration.into());
                }
                self.admit(id)?;
                if self.core.outcome().failure.is_some() {
                    self.close_cadet();
                    self.channel = None;
                    self.packet = None;
                    self.complete(id, Completion::Retired)?;
                    return Ok(true);
                }
                if self.write.is_some() {
                    return Ok(false);
                }
                if let Some(channel) = self.channel {
                    match self.cadet.destroy(channel) {
                        Ok(transmit) => {
                            self.write = Some(NativeWrite {
                                effect: Some(id),
                                transmit,
                                bytes: 0,
                                hard: self.hard()?,
                            });
                            Ok(true)
                        }
                        Err(error) if transient(&error) => Ok(false),
                        Err(cadet::Error::Protocol(Fault::Stale | Fault::Closed)) => {
                            self.channel = None;
                            self.packet = None;
                            self.complete(id, Completion::Retired)?;
                            Ok(true)
                        }
                        Err(error) => Err(error.into()),
                    }
                } else {
                    self.complete(id, Completion::Retired)?;
                    Ok(true)
                }
            }
            Action::ClosePort { port: original } => {
                if let Some(port) = self.port
                    && self.cadet.port_hash(port)? != *original
                {
                    return Err(Fault::StaleGeneration.into());
                }
                self.admit(id)?;
                if self.write.is_some() {
                    return Ok(false);
                }
                if let Some(port) = self.port {
                    match self.cadet.close_port(port) {
                        Ok(Some(transmit)) => {
                            self.write = Some(NativeWrite {
                                effect: Some(id),
                                transmit,
                                bytes: 0,
                                hard: self.hard()?,
                            });
                            Ok(true)
                        }
                        Ok(None) => {
                            self.port = None;
                            self.complete(id, Completion::Retired)?;
                            Ok(true)
                        }
                        Err(error) if transient(&error) => Ok(false),
                        Err(cadet::Error::Protocol(Fault::Stale | Fault::Closed)) => {
                            self.port = None;
                            self.complete(id, Completion::Retired)?;
                            Ok(true)
                        }
                        Err(error) => Err(error.into()),
                    }
                } else {
                    self.complete(id, Completion::Retired)?;
                    Ok(true)
                }
            }
        }
    }
}

impl<'i, 'slots> State<'i, 'slots> {
    fn close_seti(&mut self) {
        self.incoming = None;
        for mut client in [self.set.take(), self.listener.take()]
            .into_iter()
            .flatten()
        {
            let _physical = client.close();
            while let Some(event) = client.next_event() {
                if let seti::Step::LocalEnd(_, reason, submission) = event {
                    self.report.local_ends = self.report.local_ends.saturating_add(1);
                    self.report.seti_end = Some((reason, submission));
                }
            }
        }
        self.setup = None;
        self.operation = None;
        self.set_hard = None;
        self.listener_hard = None;
        self.set_partial = None;
        self.listener_partial = None;
    }
    fn close_cadet(&mut self) {
        match self.cadet.close() {
            Ok(Some(loss)) => {
                self.report.cadet_channels_retired = self
                    .report
                    .cadet_channels_retired
                    .saturating_add(loss.channels);
                if let Some(pending) = loss.pending {
                    self.report.cadet_pending_exposed = Some(pending.exposed);
                    self.report.cadet_pending_serial = Some(pending.transmit.value());
                    self.report.cadet_pending_epoch = Some(pending.transmit.epoch().value());
                }
            }
            Ok(None) => {}
            Err(error) => {
                self.dependency_undrained = true;
                self.report.cleanup.get_or_insert(error.into());
            }
        }
        self.cadet_active = false;
        self.cadet_hard = None;
        self.partial = None;
        self.port = None;
        self.reject = None;
        if self.packet.take().is_some() {
            self.report.retired_inputs = self.report.retired_inputs.saturating_add(1);
        }
    }
    fn client(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        if let Some((id, _, _)) = self.output {
            match self.io.poll_write(cx) {
                Poll::Pending => {}
                Poll::Ready(Err(error)) => return Err(error.into()),
                Poll::Ready(Ok(progress)) => {
                    if progress.origin != 0 {
                        return Err(Fault::StaleGeneration.into());
                    }
                    self.report.client_bytes = self
                        .report
                        .client_bytes
                        .checked_add(progress.bytes)
                        .ok_or(Fault::Overflow)?;
                    let output = self.output.as_mut().ok_or(Fault::Stale)?;
                    output.1 = output
                        .1
                        .checked_add(progress.bytes)
                        .ok_or(Fault::Overflow)?;
                    if progress.complete {
                        self.output = None;
                        self.complete(id, Completion::Written)?;
                    }
                    return Ok(true);
                }
            }
        }
        if self.core.outcome().client_written {
            return Ok(false);
        }
        if self.io.frame().is_some() {
            return Err(Fault::Malformed.into());
        }
        match self.io.poll_read(cx) {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(error)) => Err(error.into()),
            Poll::Ready(Ok(ReadStep::Eof)) => Err(Fault::Closed.into()),
            // One client MQ owns one original request. After its declared
            // multipart total, there is no CANCEL/keepalive/new-session frame.
            Poll::Ready(Ok(ReadStep::Progress { .. })) => Err(Fault::Malformed.into()),
        }
    }
    fn crypto(&mut self) -> Result<bool, Error> {
        if (!self.cpu && !self.core.autonomous_work()) || self.core.effect().is_some() {
            return Ok(false);
        }
        let now = self.cadet.clock().sample()?.now.as_micros();
        match self
            .core
            .step(&mut self.entropy, self.limits.work_units, now)
        {
            Ok(progress) => Ok(progress),
            Err(cause) => {
                self.cpu = false;
                let error = self
                    .entropy
                    .take_error()
                    .map_or_else(|| self.core_error(cause), Error::Entropy);
                self.report.primary.get_or_insert(error);
                if self.core.outcome().failure.is_none() {
                    let source = self.core.peer_source();
                    self.close_cadet();
                    self.write = None;
                    if let Some(source) = source {
                        self.core
                            .peer_lost(source, cause)
                            .map_err(|cause| self.core_error(cause))?;
                    } else {
                        return Err(self.core_error(cause));
                    }
                }
                Ok(true)
            }
        }
    }
    fn arm(&mut self, cx: &mut Context<'_>) {
        let at = Some(self.native_until)
            .into_iter()
            .chain(self.write.as_ref().map(|write| write.hard))
            .chain(self.output.as_ref().map(|output| output.2))
            .chain(self.set_hard)
            .chain(self.listener_hard)
            .chain(self.set_partial)
            .chain(self.listener_partial)
            .chain(self.cadet_hard)
            .chain(self.partial)
            .min();
        if let Some(at) = at {
            self.timer.as_mut().reset(at);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
    }
    fn native_guard(&self) -> Result<(), Error> {
        // This is clock-free. It never samples, renews a target, or performs IO.
        if let Some(cause) = self.control.reason() {
            return Err(cause.into());
        }
        let now = Instant::now();
        let expired = now >= self.native_until
            || self.write.as_ref().is_some_and(|write| now >= write.hard)
            || self.output.as_ref().is_some_and(|output| now >= output.2)
            || [
                self.set_hard,
                self.listener_hard,
                self.set_partial,
                self.listener_partial,
                self.cadet_hard,
                self.partial,
            ]
            .into_iter()
            .flatten()
            .any(|at| now >= at);
        if expired {
            return Err(Fault::Deadline.into());
        }
        Ok(())
    }
    fn poll_inner(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        // Cancellation/native bounds precede every canonical sample and old IO.
        self.native_guard()?;
        if self.cadet.clock().sample()?.now.as_micros() >= self.canonical_until {
            return Err(Fault::Deadline.into());
        }
        self.native_guard()?;
        if let Some(failure) = self.core.outcome().failure
            && self.cadet_active
        {
            // A known computation failure never causes another old dependency
            // read/write. Retire even an early, still-unprocessed Bob packet
            // first; its presence must not suppress a legitimate client FAILURE.
            self.close_cadet();
            self.close_seti();
            self.channel = None;
            if let Some(write) = self.write.take()
                && let Some(id) = write.effect
            {
                let exposed = write.bytes > 0 || self.report.cadet_pending_exposed == Some(true);
                self.complete(
                    id,
                    if exposed {
                        Completion::Lost(failure.cause)
                    } else {
                        Completion::Unsent(failure.cause)
                    },
                )?;
            }
        }
        self.native_guard()?;
        if let Poll::Ready(result) = Pin::new(&mut self.deadline).poll(cx) {
            result?;
            return Err(Fault::Deadline.into());
        }
        self.native_guard()?;
        // An old packet tail is validated before admitting a terminal client
        // response. A successful first inner cannot hide a malformed later one.
        if self.peer_input()? {
            return Ok(true);
        }
        for offset in 0..5 {
            self.native_guard()?;
            let class = (self.class + offset) % 5;
            let progress = match class {
                0 => self.actions()?,
                1 => self.sets(cx)?,
                2 => self.peers(cx)?,
                3 => self.client(cx)?,
                _ => self.crypto()?,
            };
            if progress {
                self.class = (class + 1) % 5;
                return Ok(true);
            }
        }
        self.class = (self.class + 1) % 5;
        Ok(false)
    }
    fn cleanup_error(&mut self, error: Error) {
        self.report.cleanup.get_or_insert(error);
    }
    fn finish(&mut self, error: Option<Error>) -> SessionReport {
        if let Some(error) = error {
            if self.core.outcome().client_written {
                if !matches!(error.classified(), Fault::Closed | Fault::Cancelled) {
                    self.cleanup_error(error);
                }
            } else {
                self.report.primary.get_or_insert(error);
            }
        }
        let cause = self
            .report
            .primary
            .as_ref()
            .map_or(Fault::Cancelled, Error::classified);
        // Capture only immutable actual write facts, without sampling a clock.
        // Source retirement must not turn an already complete setup into Lost
        // merely because its pure composite completion was one turn later.
        let setup_written = self
            .setup
            .as_ref()
            .filter(|setup| {
                setup.listener
                    && self.set_created_written
                    && self.listen_written
                    && setup.add.is_none()
                    && matches!(
                        self.core.intersection_key(setup.intersection, setup.cursor),
                        Ok(None)
                    )
            })
            .map(|setup| setup.id);
        // All physical owners are detached before any original lease can be
        // completed/lost. This branch samples no clock and performs no IO.
        self.io.retire();
        self.close_cadet();
        self.close_seti();
        let original_source = self.core.peer_source();
        if let Some(id) = setup_written
            && self
                .core
                .effect()
                .is_some_and(|effect| effect.id == id && effect.is_admitted())
            && let Err(error) = self.complete(id, Completion::Written)
        {
            self.cleanup_error(error);
        }
        if cause == Fault::Cancelled
            && !self.core.is_quiescent()
            && let Err(error) = self.core.cancel()
            && !matches!(error, Fault::Conflict | Fault::Closed)
        {
            self.cleanup_error(error.into());
        }
        if let Some(effect) = self.core.effect()
            && effect.is_admitted()
        {
            let id = effect.id;
            let cleanup = matches!(
                effect.action,
                Action::CloseIntersection { .. }
                    | Action::ClosePeer { .. }
                    | Action::ClosePort { .. }
            );
            let exposed = match &effect.action {
                Action::ClientResult { .. } => self.output.is_some_and(|output| output.1 > 0),
                Action::ListenIntersection { .. } | Action::StartIntersection { .. } => {
                    self.setup_exposed
                        || self
                            .report
                            .seti_end
                            .is_some_and(|(_, submission)| submission == seti::Submission::Unknown)
                }
                _ => self.write.as_ref().is_some_and(|write| {
                    write.effect == Some(id)
                        && (write.bytes > 0 || self.report.cadet_pending_exposed == Some(true))
                }),
            };
            let disposition = if cleanup {
                Completion::Retired
            } else if exposed {
                Completion::Lost(cause)
            } else {
                Completion::Unsent(cause)
            };
            if let Err(error) = self.complete(id, disposition) {
                self.cleanup_error(error);
            }
        }
        self.write = None;
        self.output = None;
        self.cpu = false;
        if let Some(source) = original_source
            && cause != Fault::Cancelled
            && self.core.outcome().failure.is_none()
            && !self.core.outcome().client_written
            && self.core.peer_source() == Some(source)
            && let Err(error) = self.core.peer_lost(source, cause)
            && !matches!(error, Fault::StaleGeneration)
        {
            self.cleanup_error(error.into());
        }
        if !self.core.is_quiescent() {
            if let Err(error) = self.core.cancel()
                && !matches!(error, Fault::Conflict | Fault::Closed)
            {
                self.cleanup_error(error.into());
            }
            // Only a finite number of original resources exist. No new source
            // or ordinary action is created during closing-only retirement.
            for _ in 0..16 {
                if let Err(cause) = self.core.pump() {
                    self.cleanup_error(self.core_error(cause));
                    break;
                }
                let Some(effect) = self.core.effect() else {
                    break;
                };
                let id = effect.id;
                let cleanup = matches!(
                    effect.action,
                    Action::CloseIntersection { .. }
                        | Action::ClosePeer { .. }
                        | Action::ClosePort { .. }
                );
                if !effect.is_admitted()
                    && let Err(error) = self.core.admit_effect(id)
                {
                    self.cleanup_error(error.into());
                    break;
                }
                if let Err(error) = self.complete(
                    id,
                    if cleanup {
                        Completion::Retired
                    } else {
                        Completion::Unsent(cause)
                    },
                ) {
                    self.cleanup_error(error);
                    break;
                }
            }
        }
        self.channel = None;
        self.port = None;
        self.packet = None;
        self.incoming = None;
        self.report.physical_closed = true;
        self.report.undrained =
            usize::from(!self.core.is_quiescent()) + usize::from(self.dependency_undrained);
        self.report.outcome = Some(self.core.outcome());
        self.finished = true;
        std::mem::take(&mut self.report)
    }
    pub fn poll(&mut self, cx: &mut Context<'_>) -> Poll<SessionReport> {
        if self.finished {
            return Poll::Ready(std::mem::take(&mut self.report));
        }
        if self.core.is_quiescent() {
            return Poll::Ready(self.finish(None));
        }
        match self.poll_inner(cx) {
            Err(error) => Poll::Ready(self.finish(Some(error))),
            Ok(progress) => {
                if self.core.is_quiescent() {
                    return Poll::Ready(self.finish(None));
                }
                if progress {
                    cx.waker().wake_by_ref();
                }
                self.arm(cx);
                Poll::Pending
            }
        }
    }
}
impl Drop for State<'_, '_> {
    fn drop(&mut self) {
        if !self.finished {
            let _retirement = self.finish(Some(Fault::Cancelled.into()));
        }
    }
}

impl<'i, 'slots> State<'i, 'slots> {
    fn set_event(&mut self, listener: bool, event: seti::Step<'i>) -> Result<bool, Error> {
        match event {
            seti::Step::Connected(_) => Ok(true),
            seti::Step::Written(_, write, command) => {
                if self.setup.is_some() {
                    self.setup_exposed = true;
                }
                if listener {
                    self.listener_hard = None;
                } else {
                    self.set_hard = None;
                }
                match command {
                    seti::Command::Add => {
                        let setup = self.setup.as_mut().ok_or(Fault::Stale)?;
                        if setup.add != Some(write) {
                            return Err(Fault::StaleGeneration.into());
                        }
                        setup.add = None;
                        setup.cursor = setup.cursor.checked_add(1).ok_or(Fault::Overflow)?;
                    }
                    seti::Command::Evaluate => {
                        let setup = self.setup.take().ok_or(Fault::Stale)?;
                        if setup.listener || !setup.started {
                            return Err(Fault::Conflict.into());
                        }
                        self.complete(setup.id, Completion::Written)?;
                    }
                    seti::Command::Accept => {
                        // ACCEPT was written on the set MQ, not processed by
                        // the service. Keep the original listener MQ alive so
                        // its EOF cannot reject that still-pending request.
                        // Real DONE/FAIL or owner retirement closes both MQs.
                    }
                    seti::Command::Create => self.set_created_written = true,
                    seti::Command::Listen => self.listen_written = true,
                    seti::Command::Reject if listener => {}
                    _ => return Err(Fault::Malformed.into()),
                }
                Ok(true)
            }
            seti::Step::Incoming(incoming) => {
                self.listener_partial = None;
                if !listener {
                    return Err(Fault::Malformed.into());
                }
                if self.incoming.is_some() || self.operation.is_some() {
                    drop(incoming);
                    return Ok(true);
                }
                let peer = match incoming.request()? {
                    SetResponse::Request { peer, .. } => peer,
                    _ => return Err(Fault::Malformed.into()),
                };
                let expected = self
                    .core
                    .peer_source()
                    .map(|source| source.peer)
                    .or_else(|| {
                        self.setup
                            .as_ref()
                            .filter(|setup| setup.listener)
                            .map(|setup| setup.peer)
                    });
                if expected.is_none_or(|expected| expected != peer) {
                    drop(incoming);
                    return Ok(true);
                }
                self.incoming = Some(incoming);
                Ok(true)
            }
            seti::Step::Result(record) => {
                self.set_partial = None;
                if listener || self.operation != Some(record.operation()) || self.setup.is_some() {
                    return Err(Fault::StaleGeneration.into());
                }
                let id = self.intersection.ok_or(Fault::Stale)?;
                let peer = self.core.peer_source().ok_or(Fault::Stale)?.peer;
                match record.response()? {
                    SetResponse::Result {
                        status: seti::ipc::DEL_LOCAL,
                        data,
                        ..
                    } => {
                        if record.element_type()? != Some(0) {
                            return Err(Fault::Malformed.into());
                        }
                        let key: &[u8; 64] = data.try_into().map_err(|_| Fault::Malformed)?;
                        self.core
                            .intersection_removed(
                                id,
                                peer,
                                key,
                                self.cadet.clock().sample()?.now.as_micros(),
                            )
                            .map_err(|cause| self.core_error(cause))?;
                        self.matched = self.matched.checked_sub(1).ok_or(Fault::Malformed)?;
                    }
                    SetResponse::Result {
                        status: seti::ipc::DONE,
                        data,
                        ..
                    } => {
                        if !data.is_empty() {
                            return Err(Fault::Malformed.into());
                        }
                        self.operation = None;
                        self.core
                            .intersection_done(
                                id,
                                peer,
                                self.cadet.clock().sample()?.now.as_micros(),
                            )
                            .map_err(|cause| self.core_error(cause))?;
                        self.cpu = matches!(self.report.role, Some(Role::Alice))
                            && self.core.outcome().failure.is_none();
                        self.close_seti();
                    }
                    SetResponse::Result {
                        status: seti::ipc::FAILURE,
                        ..
                    } => {
                        self.operation = None;
                        self.core
                            .intersection_failed(id, Fault::Unavailable)
                            .map_err(|cause| self.core_error(cause))?;
                        self.cpu = false;
                        self.report
                            .primary
                            .get_or_insert(Error::Protocol(Fault::Unavailable));
                        self.close_seti();
                    }
                    _ => return Err(Fault::Malformed.into()),
                }
                Ok(true)
            }
            seti::Step::LocalEnd(_, reason, submission) => {
                self.report.local_ends = self.report.local_ends.saturating_add(1);
                self.report.seti_end = Some((reason, submission));
                Err(Error::Seti(if reason == seti::Reason::Deadline {
                    seti::Cause::Deadline
                } else {
                    seti::Cause::Closed
                }))
            }
            seti::Step::Activity(read, written) => {
                if read > 0 {
                    let until = Instant::now()
                        .checked_add(self.limits.partial_input)
                        .ok_or(Fault::Overflow)?;
                    let partial = if listener {
                        &mut self.listener_partial
                    } else {
                        &mut self.set_partial
                    };
                    partial.get_or_insert(until);
                }
                if written > 0 && self.setup.is_some() {
                    self.setup_exposed = true;
                }
                self.report.dependency_bytes = self
                    .report
                    .dependency_bytes
                    .saturating_add(read)
                    .saturating_add(written);
                Ok(true)
            }
            seti::Step::Lost(_, cause) => Err(Error::Seti(cause)),
            seti::Step::Retry(error, _) => {
                self.report.connect_retries = self.report.connect_retries.saturating_add(1);
                self.report.last_retry = Some(error);
                Ok(true)
            }
            seti::Step::Capacity => Err(Fault::Capacity.into()),
            seti::Step::Closed => Err(Fault::Closed.into()),
            seti::Step::WaitDeadline => Ok(false),
        }
    }
    fn sets(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        if self.core.outcome().failure.is_some() {
            return Ok(false);
        }
        // Both original MQs are polled fairly. No listener reconnect or SET
        // reconstruction is performed after a known physical source loss.
        let first = self.set_first;
        self.set_first = !self.set_first;
        for listener in [first, !first] {
            let client = if listener {
                self.listener.as_mut()
            } else {
                self.set.as_mut()
            };
            if let Some(client) = client {
                match set_poll(client, cx) {
                    Poll::Pending => {}
                    Poll::Ready(Err(error)) => return Err(error.into()),
                    Poll::Ready(Ok(event)) => return self.set_event(listener, event),
                }
            }
        }
        Ok(false)
    }
    fn peer_input(&mut self) -> Result<bool, Error> {
        let Some(packet) = self.packet.as_ref() else {
            return Ok(false);
        };
        if packet.processing.is_some() {
            return Ok(false);
        }
        let bytes = packet.received.messages();
        let header = bytes
            .get(packet.at..packet.at.checked_add(4).ok_or(Fault::Overflow)?)
            .ok_or(Fault::Truncated)?;
        let len = usize::from(u16::from_be_bytes([header[0], header[1]]));
        if len < 4 {
            return Err(Fault::Malformed.into());
        }
        let end = packet.at.checked_add(len).ok_or(Fault::Overflow)?;
        let frame = bytes.get(packet.at..end).ok_or(Fault::Truncated)?;
        let message = PeerMessage::decode(frame)?;
        let source = packet.source;
        let serial = self.next_input.ok_or(Fault::Overflow)?;
        match self.core.receive(
            source,
            serial,
            message,
            self.cadet.clock().sample()?.now.as_micros(),
        ) {
            Ok(input) => {
                self.next_input = serial.checked_add(1);
                self.cpu = matches!(
                    message,
                    PeerMessage::EccAlice { .. } | PeerMessage::EccBob { .. }
                );
                self.packet.as_mut().ok_or(Fault::Stale)?.processing = Some((input, serial, end));
                Ok(true)
            }
            Err(Fault::WouldBlock) => Ok(false),
            Err(error) => Err(error.into()),
        }
    }
    fn written(&mut self, transmit: cadet::Transmit<'i>) -> Result<(), Error> {
        let pending = self.write.take().ok_or(Fault::Stale)?;
        if pending.transmit != transmit {
            self.write = Some(pending);
            return Err(Fault::StaleGeneration.into());
        }
        self.cadet_hard = None;
        if let Some(id) = pending.effect {
            let effect = self.core.effect().ok_or(Fault::Stale)?;
            if effect.id != id {
                return Err(Fault::StaleGeneration.into());
            }
            match &effect.action {
                Action::PeerSend { payload, .. } => match payload.kind() {
                    PeerKind::Session => self.session_written = true,
                    PeerKind::Alice(count) => {
                        self.sent = self.sent.checked_add(count).ok_or(Fault::Overflow)?;
                        self.cpu = self.sent < self.matched;
                    }
                    PeerKind::Bob => {}
                },
                Action::ReceiveDone { .. } => {
                    self.packet = None;
                    self.cpu = false;
                    self.report.outer_acks = self.report.outer_acks.saturating_add(1);
                }
                Action::ClosePeer { .. } => {
                    self.channel = None;
                    self.packet = None;
                }
                Action::ClosePort { .. } => self.port = None,
                _ => {}
            }
            self.complete(id, Completion::Written)?;
        } else if self.reject.is_some() {
            self.reject = None;
        }
        Ok(())
    }
    fn peer_event(&mut self, event: cadet::Step<'i>) -> Result<bool, Error> {
        use cadet::Step;
        match event {
            Step::Connected(_) => Ok(true),
            Step::Written(written) => {
                self.written(written.transmit)?;
                Ok(true)
            }
            Step::Incoming { channel, port } => {
                self.partial = None;
                if self.port != Some(port)
                    || self.channel.is_some()
                    || self.core.outcome().failure.is_some()
                {
                    if self.reject.is_some() {
                        return Err(Fault::Capacity.into());
                    }
                    self.reject = Some(channel);
                    return Ok(true);
                }
                let source = self.source(channel)?;
                self.core
                    .attach_peer(source)
                    .map_err(|cause| self.core_error(cause))?;
                self.channel = Some(channel);
                Ok(true)
            }
            Step::Data(received) => {
                self.partial = None;
                if Some(received.channel()) != self.channel {
                    if self.reject != Some(received.channel()) {
                        return Err(Fault::StaleGeneration.into());
                    }
                    // The original foreign channel is physically destroyed;
                    // this unprocessed input is never acknowledged as success.
                    drop(received);
                    return Ok(true);
                }
                if self.packet.is_some() {
                    return Err(Fault::Capacity.into());
                }
                let source = self.source(received.channel())?;
                self.packet = Some(Packet {
                    received,
                    source,
                    at: 0,
                    processing: None,
                });
                Ok(true)
            }
            Step::Destroyed(channel) => {
                self.partial = None;
                if self.reject == Some(channel) {
                    self.reject = None;
                    return Ok(true);
                }
                if self.channel == Some(channel) {
                    return self.peer_destroyed(Fault::Closed.into());
                }
                Err(Fault::StaleGeneration.into())
            }
            Step::Credit { .. } | Step::Ignored { .. } => {
                self.partial = None;
                Ok(true)
            }
            Step::RejectedIncoming { transmit, .. } => {
                self.partial = None;
                if self.write.is_some() {
                    return Err(Fault::Conflict.into());
                }
                self.write = Some(NativeWrite {
                    effect: None,
                    transmit,
                    bytes: 0,
                    hard: self.hard()?,
                });
                Ok(true)
            }
            Step::Activity {
                read_bytes,
                written_bytes,
                ..
            } => {
                self.report.dependency_bytes = self
                    .report
                    .dependency_bytes
                    .saturating_add(read_bytes)
                    .saturating_add(written_bytes);
                if written_bytes > 0
                    && let Some(write) = self.write.as_mut()
                {
                    write.bytes = write
                        .bytes
                        .checked_add(written_bytes)
                        .ok_or(Fault::Overflow)?;
                }
                if read_bytes > 0 && self.partial.is_none() {
                    self.partial = Some(
                        Instant::now()
                            .checked_add(self.limits.partial_input)
                            .ok_or(Fault::Overflow)?,
                    );
                }
                Ok(true)
            }
            Step::Lost { report, cause, .. } => {
                self.report.cadet_channels_retired = self
                    .report
                    .cadet_channels_retired
                    .saturating_add(report.channels);
                self.report.cadet_pending_exposed = report.pending.map(|pending| pending.exposed);
                self.report.cadet_pending_serial =
                    report.pending.map(|pending| pending.transmit.value());
                self.report.cadet_pending_epoch = report
                    .pending
                    .map(|pending| pending.transmit.epoch().value());
                let cause = match cause {
                    cadet::LossCause::Io(error) => Error::Io(error),
                    cadet::LossCause::Protocol(error) => error.into(),
                    cadet::LossCause::Eof | cadet::LossCause::Requested => Fault::Closed.into(),
                };
                if matches!(cause.classified(), Fault::Io | Fault::Closed) {
                    self.retire_for_local_work(cause)
                } else {
                    Err(cause)
                }
            }
            Step::ConnectRetry { error, .. } => {
                self.report.connect_retries = self.report.connect_retries.saturating_add(1);
                self.report.last_retry = Some(error);
                Ok(true)
            }
            Step::Unavailable(error) => Err(error.into()),
            Step::Blocked { reason, .. } => Err(reason.into()),
            Step::Closed => self.retire_for_local_work(Fault::Closed.into()),
            Step::WaitDeadline => Ok(false),
        }
    }
    fn peer_destroyed(&mut self, error: Error) -> Result<bool, Error> {
        let held = self.packet.as_ref().is_some_and(|packet| {
            self.core.peer_source() == Some(packet.source)
                && self.core.can_drain_peer_input(packet.source)
        });
        if !held
            || self
                .write
                .as_ref()
                .is_some_and(|write| write.effect.is_some())
        {
            return self.retire_for_local_work(error);
        }
        let source = self.packet.as_ref().ok_or(Fault::Stale)?.source;
        // Only this already-received envelope survives. Stop all old IO before
        // further local work; no new channel/source/ACK or suffix is introduced.
        let packet = self.packet.take();
        self.close_cadet();
        self.close_seti();
        self.packet = packet;
        self.channel = None;
        self.report.dependency_loss.get_or_insert(error);
        if self.dependency_undrained {
            return Err(Fault::NotReady.into());
        }
        // A possible foreign-channel auxiliary write was physically retired;
        // its actual exposure is already retained in the native close report.
        self.write = None;
        self.closed_peer = Some(source);
        self.cpu = true;
        Ok(true)
    }
    fn retire_for_local_work(&mut self, error: Error) -> Result<bool, Error> {
        // Algorithm capability alone proves neither a valid complete outer
        // Delivery nor actual old-source retirement. Both are required here.
        let tail_validated = self.packet.as_ref().is_none_or(|packet| {
            packet
                .processing
                .is_some_and(|(_, _, end)| end == packet.received.messages().len())
        });
        if self.core.outcome().client_written || !self.core.can_finish_locally() || !tail_validated
        {
            return Err(error);
        }
        let Some(source) = self.core.peer_source() else {
            return Err(error);
        };
        let release = match self.core.effect() {
            Some(effect) => match &effect.action {
                Action::ReceiveDone {
                    input, delivery, ..
                } => {
                    let same = self
                        .packet
                        .as_ref()
                        .and_then(|packet| packet.processing)
                        .is_some_and(|(original, serial, _)| {
                            original == *input && serial == *delivery
                        });
                    if !same {
                        return Err(error);
                    }
                    Some((effect.id, effect.is_admitted()))
                }
                Action::ClientResult { .. } => None,
                _ => return Err(error),
            },
            None => None,
        };
        if let Some(write) = &self.write
            && write.effect.is_some()
            && write.effect != release.map(|value| value.0)
        {
            return Err(error);
        }
        let cause = error.classified();
        // Clock-free physical detach precedes bookkeeping. No new source,
        // old read/write, synthetic receive_done or refreshed target follows.
        self.close_cadet();
        self.close_seti();
        self.channel = None;
        self.report.dependency_loss.get_or_insert(error);
        if self.dependency_undrained {
            return Err(Fault::NotReady.into());
        }
        let receipt = if let Some((id, admitted)) = release {
            if !admitted {
                self.admit(id)?;
            }
            let exposed = self.write.as_ref().is_some_and(|write| {
                write.effect == Some(id)
                    && (write.bytes > 0 || self.report.cadet_pending_exposed == Some(true))
            });
            Some((
                id,
                if exposed {
                    Completion::Lost(cause)
                } else {
                    Completion::Unsent(cause)
                },
            ))
        } else {
            None
        };
        self.core
            .retire_peer_for_local_work(source, cause, receipt)
            .map_err(|cause| self.core_error(cause))?;
        if let Some((_, completion)) = receipt {
            match completion {
                Completion::Written => {
                    self.report.written = self.report.written.saturating_add(1);
                    self.report.outer_acks = self.report.outer_acks.saturating_add(1);
                }
                Completion::Unsent(_) => self.report.unsent = self.report.unsent.saturating_add(1),
                Completion::Lost(_) => self.report.lost = self.report.lost.saturating_add(1),
                _ => {}
            }
        }
        self.write = None;
        self.packet = None;
        self.closed_peer = None;
        self.cpu = true;
        Ok(true)
    }
    fn peers(&mut self, cx: &mut Context<'_>) -> Result<bool, Error> {
        if !self.cadet_active
            || self.core.outcome().failure.is_some()
            || self
                .core
                .effect()
                .is_some_and(|effect| matches!(effect.action, Action::ClientResult { .. }))
        {
            return Ok(false);
        }
        if let Some(channel) = self.reject
            && self.write.is_none()
        {
            match self.cadet.destroy(channel) {
                Ok(transmit) => {
                    self.write = Some(NativeWrite {
                        effect: None,
                        transmit,
                        bytes: 0,
                        hard: self.hard()?,
                    });
                    return Ok(true);
                }
                Err(error) if transient(&error) => {}
                Err(error) => return Err(error.into()),
            }
        }
        match self.cadet.poll(cx, None) {
            Poll::Pending => Ok(false),
            Poll::Ready(Err(error)) => Err(error.into()),
            Poll::Ready(Ok(event)) => self.peer_event(event),
        }
    }
}
