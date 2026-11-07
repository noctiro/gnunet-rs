//! The single selected channel, one immutable TX and one original RX loan.
use crate::{
    Cause,
    budget::{Budget, Start},
    options::{Mode, Settings},
};
use gnunet_cadet_host::{self as cadet, Channel, Client, Delivery, Port, Received, Transmit};
use gnunet_types::Error as Fault;
use gnunet_wire::official::{MessageHeader, message_type};
use std::time::Duration;
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};
pub(super) struct SourceMeta {
    pub epoch: u64,
    pub channels: usize,
    pub pending: Option<(u64, cadet::TransmitKind, bool)>,
}
impl std::fmt::Debug for SourceMeta {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceMeta")
            .field("epoch", &self.epoch)
            .field("channels", &self.channels)
            .field("pending", &self.pending)
            .finish()
    }
}
impl SourceMeta {
    pub(super) fn from_loss(loss: cadet::Loss<'_>) -> Self {
        Self {
            epoch: loss.epoch.value(),
            channels: loss.channels,
            pending: loss
                .pending
                .map(|row| (row.transmit.value(), row.transmit.kind(), row.exposed)),
        }
    }
}
#[derive(Default)]
pub(super) struct Report {
    pub connected: bool,
    pub channel_selected: bool,
    pub input_bytes: u64,
    pub data_admitted: u64,
    pub data_written: u64,
    pub output_written: u64,
    pub receive_done_written: u64,
    pub echoes: u64,
    pub last_echo_micros: Option<u64>,
    pub input_unsubmitted: usize,
    pub retained_receive_bytes: usize,
    pub observed_loss: Option<SourceMeta>,
    pub close_loss: Option<SourceMeta>,
    pub pending_at_close: Option<(u64, cadet::TransmitKind)>,
    pub connect_errors: [Option<std::io::Error>; 2],
    pub further_connect_errors: u64,
}
impl std::fmt::Debug for Report {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CadetReport")
            .field("connected", &self.connected)
            .field("channel_selected", &self.channel_selected)
            .field("input_bytes", &self.input_bytes)
            .field("data_admitted", &self.data_admitted)
            .field("data_written", &self.data_written)
            .field("output_written", &self.output_written)
            .field("receive_done_written", &self.receive_done_written)
            .field("echoes", &self.echoes)
            .field("last_echo_micros", &self.last_echo_micros)
            .field("input_unsubmitted", &self.input_unsubmitted)
            .field("retained_receive_bytes", &self.retained_receive_bytes)
            .field("observed_loss", &self.observed_loss)
            .field("close_loss", &self.close_loss)
            .field("pending_at_close", &self.pending_at_close)
            .field("connect_errors", &self.connect_errors)
            .field("further_connect_errors", &self.further_connect_errors)
            .finish()
    }
}
impl Report {
    pub(super) fn connection_error(&mut self, error: std::io::Error) {
        if let Some(slot) = self.connect_errors.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(error);
        } else {
            self.further_connect_errors = self.further_connect_errors.saturating_add(1);
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum Intent {
    Setup,
    PortClose,
    Input(usize),
    Echo(usize),
    Probe,
    Ack,
    Destroy,
    ExtraDestroy,
    Reject,
}
pub(super) struct Pending<'id> {
    pub token: Transmit<'id>,
    pub intent: Intent,
    pub budget: Budget,
}
struct InputFrame {
    bytes: Zeroizing<Vec<u8>>,
    used: usize,
    budget: Option<Budget>,
}
struct Rx<'id> {
    received: Received<'id>,
    at: usize,
    offset: usize,
    budget: Budget,
}
impl Rx<'_> {
    fn current(&self) -> Result<Option<(usize, &[u8])>, Fault> {
        let bytes = self.received.messages();
        if self.at == bytes.len() {
            return Ok(None);
        }
        let rest = bytes.get(self.at..).ok_or(Fault::Malformed)?;
        let header = MessageHeader::decode(rest)?;
        if header.message_type() != message_type::CADET_CLI {
            return Err(Fault::Unsupported);
        }
        let frame = rest.get(..header.size()).ok_or(Fault::Truncated)?;
        Ok(Some((header.size(), frame)))
    }
    fn advance(&mut self, size: usize) {
        self.at += size;
        self.offset = 0;
    }
}
pub(super) enum Event {
    Continue,
    End,
    Lost(cadet::LossCause),
    Failure(cadet::Error),
}
pub(super) struct State<'id> {
    pub channel: Option<Channel<'id>>,
    port: Option<Port<'id>>,
    extra: Option<Channel<'id>>,
    pub tx: Option<Pending<'id>>,
    input: InputFrame,
    rx: Option<Rx<'id>>,
    pub init: Option<Budget>,
    pub partial: Option<Budget>,
    probe: Option<Budget>,
    probe_sent: Option<Instant>,
    pub next_probe: Option<Instant>,
    pub closing: bool,
    pub close_hard: Option<Instant>,
    setup_done: bool,
    port_close: bool,
    port_budget: Option<Budget>,
    extra_budget: Option<Budget>,
}
fn transient(error: &cadet::Error) -> bool {
    matches!(
        error,
        cadet::Error::Protocol(Fault::WouldBlock | Fault::NotReady | Fault::Capacity)
    )
}
impl<'id> State<'id> {
    pub(super) fn new(settings: &Settings, initial: Budget) -> Result<Self, Cause> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(settings.chunk + 4)?;
        bytes.resize(settings.chunk + 4, 0);
        Ok(Self {
            channel: None,
            port: None,
            extra: None,
            tx: None,
            input: InputFrame {
                bytes: Zeroizing::new(bytes),
                used: 0,
                budget: None,
            },
            rx: None,
            init: Some(initial),
            partial: None,
            probe: None,
            probe_sent: None,
            next_probe: None,
            closing: false,
            close_hard: None,
            setup_done: false,
            port_close: false,
            port_budget: None,
            extra_budget: None,
        })
    }
    pub(super) fn budgets(&self) -> impl Iterator<Item = Budget> + '_ {
        [
            self.init,
            self.partial,
            self.tx.as_ref().map(|tx| tx.budget),
            self.input.budget,
            self.rx.as_ref().map(|rx| rx.budget),
            self.probe,
            self.port_budget,
            self.extra_budget,
        ]
        .into_iter()
        .flatten()
    }
    fn track(
        &mut self,
        client: &Client<'id, '_>,
        intent: Intent,
        budget: Budget,
    ) -> Result<(), cadet::Error> {
        if self.tx.is_some() {
            return Err(Fault::Conflict.into());
        }
        self.tx = Some(Pending {
            token: client.pending_transmit().ok_or(Fault::NotReady)?,
            intent,
            budget,
        });
        Ok(())
    }
    pub(super) fn start_close(
        &mut self,
        settings: &Settings,
        report: &mut Report,
    ) -> Result<(), Fault> {
        if !self.closing {
            self.close_hard = Some(
                Instant::now()
                    .checked_add(settings.cleanup)
                    .ok_or(Fault::Overflow)?,
            );
            self.closing = true;
            self.init = None;
            self.probe = None;
            self.next_probe = None;
            report.input_unsubmitted = self.input.used;
            self.input.bytes.zeroize();
            self.input.used = 0;
            self.input.budget = None;
            self.port_close = true;
        }
        Ok(())
    }
    pub(super) fn output(&self) -> Result<Option<&[u8]>, Fault> {
        let Some(rx) = &self.rx else {
            return Ok(None);
        };
        let Some((_, frame)) = rx.current()? else {
            return Ok(None);
        };
        Ok(Some(frame.get(4 + rx.offset..).ok_or(Fault::Malformed)?))
    }
    pub(super) fn can_output(&self, settings: &Settings) -> bool {
        self.rx.is_some() && !(settings.echo && matches!(settings.mode, Mode::Listen))
    }
    pub(super) fn wrote_output(&mut self, count: usize, report: &mut Report) -> Result<(), Fault> {
        if count == 0 {
            return Err(Fault::Io);
        }
        let rx = self.rx.as_mut().ok_or(Fault::NotReady)?;
        let (size, frame) = rx.current()?.ok_or(Fault::NotReady)?;
        if count > frame.len().saturating_sub(4 + rx.offset) {
            return Err(Fault::InvalidInput);
        }
        rx.offset += count;
        report.output_written = report.output_written.saturating_add(count as u64);
        if 4 + rx.offset == size {
            rx.advance(size);
        }
        Ok(())
    }
    pub(super) fn input_space(&mut self) -> &mut [u8] {
        &mut self.input.bytes[4..]
    }
    pub(super) fn can_input(&self, settings: &Settings) -> bool {
        !self.closing
            && !settings.echo
            && self.channel.is_some()
            && self.setup_done
            && self.input.used == 0
            && self.tx.is_none()
    }
    pub(super) fn read_input(
        &mut self,
        count: usize,
        budget: Budget,
        report: &mut Report,
    ) -> Result<(), Fault> {
        if count == 0 {
            return Err(Fault::InvalidInput);
        }
        MessageHeader::new(message_type::CADET_CLI, count)?.encode(&mut self.input.bytes[..4])?;
        self.input.used = count;
        self.input.budget = Some(budget);
        report.input_bytes = report.input_bytes.saturating_add(count as u64);
        Ok(())
    }
    pub(super) fn step(
        &mut self,
        step: cadet::Step<'id>,
        start: Start,
        settings: &Settings,
        report: &mut Report,
    ) -> Result<Event, Cause> {
        match step {
            cadet::Step::Connected(_) => report.connected = true,
            cadet::Step::Written(written) => {
                let pending = self.tx.take().ok_or(Fault::StaleGeneration)?;
                if pending.token != written.transmit {
                    self.tx = Some(pending);
                    return Err(Fault::StaleGeneration.into());
                }
                match pending.intent {
                    Intent::Setup => {
                        self.setup_done = true;
                        self.init = None;
                        if settings.echo && matches!(settings.mode, Mode::Connect(_)) {
                            self.next_probe = Some(Instant::now());
                        }
                    }
                    Intent::PortClose => {
                        self.port = None;
                        self.port_close = false;
                        self.port_budget = None;
                    }
                    Intent::Input(bytes) | Intent::Echo(bytes) => {
                        report.data_written = report.data_written.saturating_add(bytes as u64)
                    }
                    Intent::Ack => {
                        report.receive_done_written = report.receive_done_written.saturating_add(1)
                    }
                    Intent::Destroy => {
                        self.channel = None;
                    }
                    Intent::ExtraDestroy => {
                        self.extra = None;
                        self.extra_budget = None;
                    }
                    Intent::Probe | Intent::Reject => {}
                }
            }
            cadet::Step::Incoming { channel, .. } => {
                self.partial = None;
                if self.channel.is_none() && matches!(settings.mode, Mode::Listen) && !self.closing
                {
                    self.channel = Some(channel);
                    self.port_close = true;
                    self.port_budget = Some(start.budget(settings.operation)?);
                    report.channel_selected = true;
                } else {
                    if self.extra.is_some() {
                        return Err(Fault::Capacity.into());
                    }
                    self.extra = Some(channel);
                    self.extra_budget = Some(start.budget(settings.operation)?);
                }
            }
            cadet::Step::Destroyed(channel) => {
                self.partial = None;
                if self.channel == Some(channel) {
                    self.channel = None;
                    return Ok(Event::End);
                }
                if self.extra == Some(channel) {
                    self.extra = None;
                    self.extra_budget = None;
                }
            }
            cadet::Step::Credit { .. } | cadet::Step::Ignored { .. } => self.partial = None,
            cadet::Step::Data(received) => {
                self.partial = None;
                if self.closing {
                    drop(received);
                    return Ok(Event::Continue);
                }
                if self.channel != Some(received.channel()) {
                    drop(received);
                    return Ok(Event::Continue);
                }
                if self.rx.is_some() {
                    return Err(Fault::Conflict.into());
                }
                let budget = start.budget(settings.operation)?;
                let rx = Rx {
                    received,
                    at: 0,
                    offset: 0,
                    budget,
                };
                let _actual_header = rx.current()?;
                if settings.echo && matches!(settings.mode, Mode::Connect(_)) {
                    if let Some(sent) = self.probe_sent.take() {
                        report.last_echo_micros = Some(
                            u64::try_from(Instant::now().duration_since(sent).as_micros())
                                .unwrap_or(u64::MAX),
                        );
                        report.echoes = report.echoes.saturating_add(1);
                    }
                    self.probe = None;
                    if !self.closing {
                        self.next_probe = Some(
                            Instant::now()
                                .checked_add(Duration::from_secs(1))
                                .ok_or(Fault::Overflow)?,
                        );
                    }
                }
                self.rx = Some(rx);
            }
            cadet::Step::RejectedIncoming { transmit, .. } => {
                self.partial = None;
                if self.tx.is_some() {
                    return Err(Fault::Conflict.into());
                }
                self.tx = Some(Pending {
                    token: transmit,
                    intent: Intent::Reject,
                    budget: start.budget(settings.operation)?,
                });
            }
            cadet::Step::Blocked { input_retained, .. } => {
                if input_retained && self.partial.is_none() {
                    self.partial = Some(start.budget(settings.operation)?);
                }
            }
            cadet::Step::Activity { read_bytes, .. } => {
                if read_bytes != 0 && self.partial.is_none() {
                    self.partial = Some(start.budget(settings.operation)?);
                }
            }
            cadet::Step::Lost {
                report: loss,
                cause,
                ..
            } => {
                report.observed_loss = Some(SourceMeta::from_loss(loss));
                return Ok(Event::Lost(cause));
            }
            cadet::Step::ConnectRetry { error, .. } => report.connection_error(error),
            cadet::Step::Unavailable(error) => return Ok(Event::Failure(error)),
            cadet::Step::Closed => return Ok(Event::End),
            cadet::Step::WaitDeadline => {}
        }
        Ok(Event::Continue)
    }
    /// At most one actual port admission, with native/clock checks made by caller.
    pub(super) fn admit(
        &mut self,
        client: &mut Client<'id, '_>,
        start: Start,
        settings: &Settings,
        report: &mut Report,
    ) -> Result<bool, Cause> {
        if self.tx.is_some() || client.pending_transmit().is_some() {
            return Ok(false);
        }
        let operation = start.budget(settings.operation)?;
        let result = (|| -> Result<bool, cadet::Error> {
            if !self.setup_done && self.channel.is_none() && self.port.is_none() && !self.closing {
                match settings.mode {
                    Mode::Listen => self.port = Some(client.listen(settings.port)?),
                    Mode::Connect(peer) => {
                        self.channel = Some(client.open(peer, settings.port)?);
                        report.channel_selected = true;
                    }
                }
                self.track(client, Intent::Setup, self.init.ok_or(Fault::NotReady)?)?;
                return Ok(true);
            }
            if let Some(rx) = self.rx.as_mut() {
                // Empty messages need no stdout syscall, but still owe the exact
                // original delivery credit. Multiple inner messages remain ordered.
                loop {
                    match rx.current()? {
                        Some((size, frame))
                            if frame.len() == 4
                                && !(settings.echo && matches!(settings.mode, Mode::Listen)) =>
                        {
                            rx.advance(size)
                        }
                        _ => break,
                    }
                }
                if let Some((size, frame)) = rx.current()? {
                    if settings.echo && matches!(settings.mode, Mode::Listen) {
                        let channel = rx.received.channel();
                        let budget = rx.budget;
                        let bytes = frame.len() - 4;
                        let token = client.send(channel, 0, frame)?;
                        rx.advance(size);
                        self.tx = Some(Pending {
                            token,
                            intent: Intent::Echo(bytes),
                            budget,
                        });
                        report.data_admitted = report.data_admitted.saturating_add(bytes as u64);
                        return Ok(true);
                    }
                } else {
                    let delivery: Delivery<'id> = rx.received.delivery();
                    let budget = rx.budget;
                    if self.channel == Some(delivery.channel()) {
                        let token = client.receive_done(delivery)?;
                        self.tx = Some(Pending {
                            token,
                            intent: Intent::Ack,
                            budget,
                        });
                    }
                    drop(self.rx.take());
                    return Ok(true);
                }
            }
            if let Some(extra) = self.extra {
                let token = client.destroy(extra)?;
                self.tx = Some(Pending {
                    token,
                    intent: Intent::ExtraDestroy,
                    budget: self.extra_budget.unwrap_or(operation),
                });
                return Ok(true);
            }
            if self.port_close
                && let Some(port) = self.port
            {
                match client.close_port(port)? {
                    Some(token) => {
                        self.tx = Some(Pending {
                            token,
                            intent: Intent::PortClose,
                            budget: self.port_budget.unwrap_or(operation),
                        })
                    }
                    None => {
                        self.port = None;
                        self.port_close = false;
                        self.port_budget = None;
                    }
                }
                return Ok(true);
            }
            if !self.closing && self.input.used != 0 {
                let channel = self.channel.ok_or(Fault::NotReady)?;
                let bytes = self.input.used;
                let budget = self.input.budget.ok_or(Fault::NotReady)?;
                let token = client.send(channel, 0, &self.input.bytes[..bytes + 4])?;
                self.tx = Some(Pending {
                    token,
                    intent: Intent::Input(bytes),
                    budget,
                });
                self.input.bytes[..bytes + 4].zeroize();
                self.input.used = 0;
                self.input.budget = None;
                report.data_admitted = report.data_admitted.saturating_add(bytes as u64);
                return Ok(true);
            }
            if !self.closing
                && settings.echo
                && matches!(settings.mode, Mode::Connect(_))
                && self.probe_sent.is_none()
                && self.next_probe.is_some_and(|at| Instant::now() >= at)
            {
                let budget = *self.probe.get_or_insert(operation);
                let mut frame = [0; 4];
                MessageHeader::new(message_type::CADET_CLI, 0)?.encode(&mut frame)?;
                let token = client.send(self.channel.ok_or(Fault::NotReady)?, 0, &frame)?;
                self.tx = Some(Pending {
                    token,
                    intent: Intent::Probe,
                    budget,
                });
                self.probe_sent = Some(start.native());
                self.next_probe = None;
                return Ok(true);
            }
            if self.closing
                && self.rx.is_none()
                && let Some(channel) = self.channel
            {
                let token = client.destroy(channel)?;
                self.tx = Some(Pending {
                    token,
                    intent: Intent::Destroy,
                    budget: operation,
                });
                return Ok(true);
            }
            Ok(false)
        })();
        match result {
            Ok(progress) => Ok(progress),
            Err(error) if transient(&error) => Ok(false),
            Err(error) => Err(Box::new(error)),
        }
    }
    pub(super) fn probe_wakeup(&self) -> Option<Instant> {
        if self.probe.is_none() && self.tx.is_none() && self.rx.is_none() {
            self.next_probe
        } else {
            None
        }
    }
    pub(super) fn finished(&self) -> bool {
        self.closing
            && self.tx.is_none()
            && self.rx.is_none()
            && self.channel.is_none()
            && self.port.is_none()
            && self.extra.is_none()
    }
    pub(super) fn final_metadata(&self, report: &mut Report) {
        report.input_unsubmitted = report.input_unsubmitted.saturating_add(self.input.used);
        report.retained_receive_bytes = self
            .rx
            .as_ref()
            .map_or(0, |rx| rx.received.messages().len());
        report.pending_at_close = self
            .tx
            .as_ref()
            .map(|tx| (tx.token.value(), tx.token.kind()));
    }
}
