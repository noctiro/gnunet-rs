//! Atomic native sends, original result ownership and endpoint retirement.
use super::*;

impl Communicator<'_> {
    pub(super) fn fail_endpoint_send(
        &mut self,
        index: usize,
        failure: OwnedFrame,
    ) -> Result<(), Error> {
        // A negative SEND result makes TRANSPORT discard the QID. Both KX
        // and BOX share this sender generation, so neither may keep granting
        // credit or make a later CREATE appear to have a live queue. Preserve
        // the original failure first, then let bounded maintenance drain the
        // existing generation's completion and DOWNs without replaying it.
        if self.endpoints.get(index).is_none_or(Option::is_none) {
            return Err(Error::Stale);
        }
        self.push(failure, Origin::Effect)?;
        self.endpoints[index].as_mut().ok_or(Error::Stale)?.retiring = true;
        Ok(())
    }

    pub(super) fn transmit(
        &mut self,
        cx: &mut Context<'_>,
        now: u64,
    ) -> Poll<Result<Activity, Failure>> {
        for offset in 0..self.sockets.len() {
            let socket = (self.tx_cursor + offset) % self.sockets.len();
            let Some(completion) = self.completions[socket].as_ref() else {
                continue;
            };
            let index = completion.endpoint;
            let endpoint = self.endpoints[index].as_ref().ok_or(Error::Stale)?;
            if endpoint.generation != completion.generation {
                return Poll::Ready(Err(Error::Stale.into()));
            }
            // A retained send can outlive its preparation while the socket is
            // backpressured. Check the same live endpoint's actual ACK target
            // before every native retry, even when transmission wins the fair
            // turn before maintenance. Retirement preserves the original failure.
            if endpoint.retiring
                || now.saturating_sub(endpoint.last_ack)
                    >= self.configuration.transmit.acknowledgement_timeout_us
            {
                if let Some(activity) = self.retire_endpoint(index)? {
                    self.tx_cursor = (socket + 1) % self.sockets.len();
                    return Poll::Ready(Ok(activity));
                }
                continue;
            }
            let result = match self.sockets[socket].poll_send(cx) {
                Poll::Pending => continue,
                Poll::Ready(result) => result,
            };
            self.tx_cursor = (socket + 1) % self.sockets.len();
            let completion = self.completions[socket].take().ok_or(Error::Stale)?;
            match result {
                Ok(sent) => {
                    if sent.operation != completion.operation || sent.target != completion.target {
                        self.fail_endpoint_send(index, completion.failure)?;
                        return Poll::Ready(Err(Error::Stale.into()));
                    }
                    self.push(completion.success, Origin::Effect)?;
                    return Poll::Ready(Ok(Activity::NativeSent {
                        peer: completion.peer,
                        target: completion.target,
                        mode: completion.mode,
                        bytes: sent.bytes,
                    }));
                }
                Err(error) => {
                    drop(self.sockets[socket].cancel_send());
                    self.fail_endpoint_send(index, completion.failure)?;
                    return match error {
                        SocketError::Io(error)
                            if gnunet_native::network::isolated_datagram_send_error(&error) =>
                        {
                            Poll::Ready(Ok(Activity::SendError {
                                socket,
                                peer: completion.peer,
                                target: completion.target,
                                error,
                            }))
                        }
                        error => Poll::Ready(Err(error.into())),
                    };
                }
            }
        }
        Poll::Pending
    }
    pub(super) fn retire_endpoint(&mut self, index: usize) -> Result<Option<Activity>, Failure> {
        if self.endpoints[index].as_ref().is_some_and(|endpoint| {
            endpoint.source_generation != self.publication_source.generation
        }) {
            return self.drop_detached_endpoint(index).map(Some);
        }
        let Some(endpoint) = self.endpoints[index].as_mut() else {
            return Ok(None);
        };
        // Retirement is terminal for this generation, including while failure
        // and queue-down effects are backpressured. No later ACK or command may
        // revive the sender between those bounded steps.
        endpoint.retiring = true;
        let endpoint = self.endpoints[index].as_ref().ok_or(Error::Stale)?;
        let socket = endpoint.socket;
        let has_completion = self.completions[socket].as_ref().is_some_and(|completion| {
            completion.endpoint == index && completion.generation == endpoint.generation
        });
        if has_completion {
            // Release this completion's reserved slots with its original failure
            // first. Requiring both queue-down frames in the same step can exceed
            // the valid four-frame budget while another socket also owns a TX.
            if !self.room_without(1, 52, Some(socket)) {
                return Ok(None);
            }
            let completion = self.completions[socket].take().ok_or(Error::Stale)?;
            drop(self.sockets[socket].cancel_send());
            self.push(completion.failure, Origin::Effect)?;
            return Ok(Some(Activity::Command));
        }
        let frames = 1 + usize::from(endpoint.boxed.is_some());
        let bytes = 40 + usize::from(endpoint.boxed.is_some()) * 40;
        if !self.room(frames, bytes) {
            return Ok(None);
        }
        let queue = Self::queue_for(endpoint, endpoint.kx, 0, false)?;
        let kx = frozen(40, |out| queue.down(out))?;
        let boxed = if let Some(id) = endpoint.boxed {
            let queue = Self::queue_for(endpoint, id, 0, true)?;
            Some(frozen(40, |out| queue.down(out))?)
        } else {
            None
        };
        let mut endpoint = self.endpoints[index].take().ok_or(Error::Stale)?;
        endpoint.sender.close();
        if socket >= self.defaults
            && !self
                .endpoints
                .iter()
                .flatten()
                .any(|other| other.socket == socket)
        {
            self.sockets[socket].close();
        }
        self.push(kx, Origin::Effect)?;
        if let Some(frame) = boxed {
            self.push(frame, Origin::Effect)?;
        }
        if self.restoring {
            // A queue withdrawn during recovery remains part of that actual
            // publication prefix until its final DOWN is wholly written.
            self.restore_fence = self.next_effect;
        }
        Ok(Some(Activity::Retired))
    }
}
