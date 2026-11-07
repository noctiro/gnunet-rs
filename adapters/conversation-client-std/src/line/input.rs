use super::*;
use crate::Audio;
use gnunet_service_runtime::framing::ReadStep;

enum Input {
    Ring {
        cid: [u8; 4],
        key: [u8; 36],
    },
    Control {
        cid: [u8; 4],
        action: ipc::ClientControl,
    },
    Audio {
        cid: [u8; 4],
        frame: OwnedFrame,
        lease: crate::audio::Lease,
    },
    Ignore([u8; 4]),
}
impl Line {
    fn cid_row(&self, cid: [u8; 4]) -> Option<usize> {
        self.rows
            .iter()
            .position(|r| r.as_ref().is_some_and(|r| r.info.cid == Some(cid)))
    }
    fn remember_room(&mut self) -> Result<(), Error> {
        if self.seen.len() >= self.limits.call_ids {
            return Err(Fault::Capacity.into());
        }
        if self.seen.len() == self.seen.capacity() {
            let old = self.seen.capacity();
            let proposed = old.saturating_mul(2).max(4).min(self.limits.call_ids);
            let available = self
                .limits
                .retained_bytes
                .checked_sub(self.retained_bytes()?)
                .ok_or(Fault::Capacity)?;
            let n = if proposed
                .saturating_sub(old)
                .checked_mul(4)
                .ok_or(Fault::Overflow)?
                <= available
            {
                proposed
            } else {
                self.seen.len() + 1
            };
            if n.saturating_sub(old)
                .checked_mul(4)
                .ok_or(Fault::Overflow)?
                > available
            {
                return Err(Fault::Capacity.into());
            }
            self.seen
                .try_reserve_exact(n - self.seen.len())
                .map_err(|_| Fault::Capacity)?;
            if self.retained_bytes()? > self.limits.retained_bytes {
                return Err(Fault::Capacity.into());
            }
        }
        Ok(())
    }
    fn parsed(&self) -> Result<Input, Error> {
        let frame = self
            .channel
            .framing()
            .and_then(|f| f.frame())
            .ok_or(Fault::NotReady)?;
        match ipc::Message::decode(frame)? {
            ipc::Message::Ring { cid, public_key } => {
                if self.mode != Mode::Register {
                    return Err(Fault::Malformed.into());
                }
                let key: [u8; 36] = public_key.try_into().map_err(|_| Fault::Malformed)?;
                gnunet_wire::official::identity::KeyType::from_value(u32::from_be_bytes(
                    key[..4].try_into().map_err(|_| Fault::Malformed)?,
                ))?;
                Ok(Input::Ring {
                    cid: cid.to_be_bytes(),
                    key,
                })
            }
            ipc::Message::Control { cid, action } => {
                if action == ipc::ClientControl::PickUp {
                    return Err(Fault::Malformed.into());
                }
                if action == ipc::ClientControl::PickedUp && self.mode != Mode::Call {
                    return Err(Fault::Malformed.into());
                }
                Ok(Input::Control {
                    cid: cid.to_be_bytes(),
                    action,
                })
            }
            ipc::Message::Audio { cid, data } => {
                let cid = cid.to_be_bytes();
                if data.len() > self.limits.audio_bytes {
                    return Err(Fault::TooLarge.into());
                }
                let Some(at) = self.cid_row(cid) else {
                    return Ok(Input::Ignore(cid));
                };
                let row = self.rows[at].as_ref().ok_or(Fault::StaleGeneration)?;
                if matches!(row.info.phase, Phase::Ended | Phase::Ending)
                    || row.info.suspended_local
                    || row.info.suspended_remote
                {
                    return Ok(Input::Ignore(cid));
                }
                if row.info.phase != Phase::Connected {
                    return Err(Fault::Malformed.into());
                }
                if self
                    .retained_bytes()?
                    .checked_add(frame.len())
                    .ok_or(Fault::Overflow)?
                    > self.limits.retained_bytes
                {
                    return Err(Fault::Capacity.into());
                }
                let copied = OwnedFrame::copy_from(frame)?;
                if copied.retained_bytes() > self.limits.frame_bytes
                    || self
                        .retained_bytes()?
                        .checked_add(copied.retained_bytes())
                        .ok_or(Fault::Overflow)?
                        > self.limits.retained_bytes
                {
                    return Err(Fault::Capacity.into());
                }
                let lease = self.audio.reserve(copied.retained_bytes())?;
                Ok(Input::Audio {
                    cid,
                    frame: copied,
                    lease,
                })
            }
            _ => Err(Fault::Malformed.into()),
        }
    }
    fn notification(&mut self) -> Result<Progress, Error> {
        let parsed = self.parsed()?;
        let epoch = self.epoch.clone().ok_or(Fault::StaleGeneration)?;
        let mut ring_slot = None;
        let mut seen_at = None;
        let mut control_slot = None;
        let mut bind = false;
        match &parsed {
            Input::Ring { cid, .. } => {
                seen_at = Some(self.seen.binary_search(cid).err().ok_or(Fault::Replay)?);
                ring_slot = Some(
                    self.rows
                        .iter()
                        .position(Option::is_none)
                        .ok_or(Fault::Capacity)?,
                );
                self.next_call.checked_add(1).ok_or(Fault::Overflow)?;
                self.remember_room()?;
            }
            Input::Control { cid, action } => {
                control_slot = self.cid_row(*cid);
                if control_slot.is_none() && self.mode == Mode::Call {
                    let slot = self.rows.iter().position(|r| {
                        r.as_ref()
                            .is_some_and(|r| r.info.role == Role::Outgoing && r.info.cid.is_none())
                    });
                    if let Some(at) = slot {
                        if !matches!(
                            action,
                            ipc::ClientControl::PickedUp | ipc::ClientControl::HangUp
                        ) {
                            return Err(Fault::Malformed.into());
                        }
                        self.remember_room()?;
                        control_slot = Some(at);
                        bind = true;
                    }
                }
                if let Some(at) = control_slot {
                    let row = self.rows[at].as_ref().ok_or(Fault::StaleGeneration)?;
                    if row.info.phase != Phase::Ended {
                        match action {
                            ipc::ClientControl::PickedUp
                                if row.info.role == Role::Outgoing
                                    && matches!(row.info.phase, Phase::Calling | Phase::Ending) => {
                            }
                            ipc::ClientControl::HangUp => {}
                            ipc::ClientControl::Suspend
                                if matches!(row.info.phase, Phase::Connected | Phase::Ending)
                                    && !row.info.suspended_remote => {}
                            ipc::ClientControl::Resume
                                if matches!(row.info.phase, Phase::Connected | Phase::Ending)
                                    && row.info.suspended_remote => {}
                            _ => return Err(Fault::Malformed.into()),
                        }
                    }
                }
            }
            Input::Audio { .. } | Input::Ignore(_) => {}
        }
        self.check()?;
        if !self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .release_frame()
        {
            return Err(Fault::Conflict.into());
        }
        self.input = None;
        self.input_bytes = 0;
        match parsed {
            Input::Ring { cid, key } => {
                let at = ring_slot.ok_or(Fault::Conflict)?;
                let call = Call {
                    domain: self.domain.clone(),
                    serial: self.next_call,
                };
                let info = CallInfo {
                    call,
                    epoch: Some(epoch),
                    role: Role::Incoming,
                    phase: Phase::Ringing,
                    cid: Some(cid),
                    caller: Some(key),
                    target: None,
                    suspended_local: false,
                    suspended_remote: false,
                    pickup_written: false,
                    remote_pickup: false,
                    hangup_written: false,
                    hangup_notified: false,
                };
                self.seen.insert(seen_at.ok_or(Fault::Conflict)?, cid);
                self.next_call += 1;
                self.rows[at] = Some(Row {
                    info: info.clone(),
                    control: None,
                });
                Ok(Progress::Ring { info })
            }
            Input::Control { cid, action } => {
                let Some(at) = control_slot else {
                    return Ok(Progress::Ignored { epoch, cid });
                };
                if bind {
                    self.seen.push(cid);
                }
                let row = self.rows[at].as_mut().ok_or(Fault::StaleGeneration)?;
                if bind {
                    row.info.cid = Some(cid);
                }
                if row.info.phase == Phase::Ended {
                    if action == ipc::ClientControl::HangUp {
                        row.info.hangup_notified = true;
                        return Ok(Progress::HangUp {
                            info: row.info.clone(),
                        });
                    }
                    return Ok(Progress::Ignored { epoch, cid });
                }
                match action {
                    ipc::ClientControl::PickedUp => {
                        row.info.remote_pickup = true;
                        if row.info.phase != Phase::Ending {
                            row.info.phase = Phase::Connected;
                        }
                        Ok(Progress::PickedUp {
                            info: row.info.clone(),
                        })
                    }
                    ipc::ClientControl::HangUp => {
                        row.info.hangup_notified = true;
                        row.info.phase = Phase::Ended;
                        let info = row.info.clone();
                        let partial = self.pending.iter().any(|p| {
                            p.receipt.call.as_ref() == Some(&info.call)
                                && p.receipt.written_bytes != 0
                        });
                        if partial {
                            self.pending_loss =
                                Some(self.lost(Cause::CallEnded(info.call.clone())));
                        }
                        Ok(Progress::HangUp { info })
                    }
                    ipc::ClientControl::Suspend => {
                        row.info.suspended_remote = true;
                        Ok(Progress::Suspended {
                            info: row.info.clone(),
                        })
                    }
                    ipc::ClientControl::Resume => {
                        row.info.suspended_remote = false;
                        Ok(Progress::Resumed {
                            info: row.info.clone(),
                        })
                    }
                    _ => Err(Fault::Malformed.into()),
                }
            }
            Input::Audio { cid, frame, lease } => {
                let at = self.cid_row(cid).ok_or(Fault::StaleGeneration)?;
                let info = self.rows[at]
                    .as_ref()
                    .ok_or(Fault::StaleGeneration)?
                    .info
                    .clone();
                Ok(Progress::Audio {
                    info,
                    audio: Audio {
                        frame,
                        _lease: lease,
                    },
                })
            }
            Input::Ignore(cid) => Ok(Progress::Ignored { epoch, cid }),
        }
    }
    pub(super) fn read(&mut self, cx: &mut Context<'_>) -> Poll<Result<Progress, Error>> {
        if self.channel.framing().and_then(|f| f.frame()).is_some() {
            let frame = self
                .channel
                .framing()
                .and_then(|f| f.frame())
                .ok_or(Fault::Conflict)?;
            if matches!(ipc::Message::decode(frame)?, ipc::Message::Audio { .. })
                && !self.audio.ready(cx, self.limits.frame_bytes)?
            {
                return Poll::Pending;
            }
            return Poll::Ready(self.notification());
        }
        match self
            .channel
            .framing_mut()
            .ok_or(Fault::NotReady)?
            .poll_read(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error.into())),
            Poll::Ready(Ok(ReadStep::Eof)) => {
                Poll::Ready(Ok(Progress::Lost(self.lost(Cause::Eof))))
            }
            Poll::Ready(Ok(ReadStep::Progress { bytes, complete })) => {
                self.input_bytes = self.input_bytes.checked_add(bytes).ok_or(Fault::Overflow)?;
                if complete {
                    self.input = None;
                } else if bytes != 0 && self.input.is_none() {
                    self.input = Some(Bound::phase(
                        self.source.clock().as_ref(),
                        self.limits.input_timeout,
                        self.overall.targets,
                    )?);
                }
                if self.retained_bytes()? > self.limits.retained_bytes {
                    return Poll::Ready(Err(Fault::Capacity.into()));
                }
                Poll::Ready(Ok(Progress::Activity {
                    epoch: self.epoch.clone().ok_or(Fault::StaleGeneration)?,
                    bytes,
                }))
            }
        }
    }
}
