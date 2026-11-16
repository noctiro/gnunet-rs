//! Bounded original effect admission under explicit caller-supplied deadlines.
use super::*;
fn transient(error: &cadet::Error) -> bool {
    matches!(
        error,
        cadet::Error::Protocol(Fault::WouldBlock | Fault::NotReady | Fault::Capacity)
    )
}
impl<'id> State<'id> {
    /// At most one actual port admission, with native/clock checks made by caller.
    pub(crate) fn admit(
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
}
