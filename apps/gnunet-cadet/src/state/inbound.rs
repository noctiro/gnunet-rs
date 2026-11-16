//! Actual inbound and fully written observations update the original state.
use super::*;
impl<'id> State<'id> {
    pub(crate) fn step(
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
}
