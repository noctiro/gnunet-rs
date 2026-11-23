//! Staged candidate preparation; socket and queue promotion share one commit.
use super::*;
use crate::communicator::EndpointPlanError;
impl<'id> Communicator<'id> {
    pub(super) fn take_burst_selection(&mut self) -> Result<(), super::super::Failure> {
        let port = self.burst.as_mut().ok_or(Error::Stale)?;
        let Active { command, phase } = port.active.take().ok_or(Error::Stale)?;
        let Phase::Running(mut owner) = phase else {
            port.active = Some(Active { command, phase });
            return Err(Error::Stale.into());
        };
        let selection = owner.take_selection().ok_or(Error::Stale)?;
        let end = owner.into_end().ok_or(Error::Stale)?;
        if !matches!(end.cause, native::Cause::Selected) {
            return Err(Error::Stale.into());
        }
        port.active = Some(Active {
            command,
            phase: Phase::Selected(Chosen {
                selection,
                scan: end.report,
            }),
        });
        Ok(())
    }
    fn reject_burst_candidate(
        &mut self,
        command: Command,
        scan: native::Report,
        reason: Refusal,
    ) -> Result<Option<Activity>, super::super::Failure> {
        self.burst.as_mut().ok_or(Error::Stale)?.active = Some(Active {
            command,
            phase: Phase::Retired(Retired {
                outcome: Outcome::Rejected { scan, reason },
                input: None,
            }),
        });
        self.burst_retired(None)
    }
    pub(super) fn handoff_burst(
        &mut self,
        now: u64,
        classify: &mut impl FnMut(SocketAddr) -> io::Result<u32>,
    ) -> Result<Option<Activity>, super::super::Failure> {
        if !self.room(2, 256) {
            return Ok(None);
        }
        let active = self
            .burst
            .as_ref()
            .and_then(|port| port.active.as_ref())
            .ok_or(Error::Stale)?;
        if Instant::now() >= active.command.hard {
            return self.burst_retired(Some(Error::Deadline));
        }
        let Phase::Selected(chosen) = &active.phase else {
            return Err(Error::Stale.into());
        };
        let peer = active.command.peer;
        let target = chosen.selection.remote;
        let index = if chosen.selection.id.is_default() {
            active.command.default
        } else {
            self.sockets
                .iter()
                .enumerate()
                .skip(self.defaults)
                .find_map(|(index, socket)| {
                    (socket.is_closed()
                        && self.completions[index].is_none()
                        && !self
                            .endpoints
                            .iter()
                            .flatten()
                            .any(|endpoint| endpoint.socket == index))
                    .then_some(index)
                })
                .unwrap_or(self.sockets.len())
        };
        if index >= self.defaults + self.configuration.endpoints {
            return Ok(None);
        }
        if self.endpoints.iter().flatten().any(|endpoint| {
            endpoint.peer == peer
                && endpoint.target == target
                && endpoint.socket == index
                && endpoint.retiring
        }) {
            return Ok(None);
        }
        let existing = self.endpoints.iter().flatten().any(|endpoint| {
            endpoint.peer == peer && endpoint.target == target && endpoint.socket == index
        });
        if !existing && !self.endpoints.iter().any(Option::is_none) {
            return Ok(None);
        }
        let finish = frozen(4, transport::burst_finished)?;
        let Active { command, phase } = self
            .burst
            .as_mut()
            .ok_or(Error::Stale)?
            .active
            .take()
            .ok_or(Error::Stale)?;
        let Phase::Selected(Chosen { selection, scan }) = phase else {
            self.burst.as_mut().ok_or(Error::Stale)?.active = Some(Active { command, phase });
            return Err(Error::Stale.into());
        };
        // The selected owner stays local until every provider/bound check has
        // passed. A refusal drops it without publishing an endpoint or frame.
        let staged_scan = match selection.socket {
            SelectedSocket::Default(_clone) => None,
            SelectedSocket::Scan(actual) => match DatagramSocket::adopt(
                actual,
                self.sockets[command.default].socket_policy().clone(),
            ) {
                Ok(socket) => Some(socket),
                Err(error) => {
                    return self.reject_burst_candidate(command, scan, Refusal::Socket(error));
                }
            },
        };
        let profile = match &staged_scan {
            Some(socket) => socket.profile(),
            None => self.sockets[index].profile(),
        };
        let plan = match self.prepare_endpoint_profile(peer, target, index, profile, now, classify)
        {
            Ok(plan) => plan,
            Err(EndpointPlanError::Protocol(error)) => {
                drop(staged_scan);
                return self.reject_burst_candidate(command, scan, Refusal::Protocol(error));
            }
            Err(EndpointPlanError::Classification(error)) => {
                drop(staged_scan);
                return self.reject_burst_candidate(command, scan, Refusal::Classification(error));
            }
        };
        if Instant::now() >= command.hard {
            drop(plan);
            drop(staged_scan);
            return self.reject_burst_candidate(command, scan, Refusal::Protocol(Error::Deadline));
        }
        match plan {
            EndpointAdmission::New(plan) => self.commit_endpoint(plan)?,
            EndpointAdmission::Live => {}
            EndpointAdmission::Retiring => return Err(Error::Stale.into()),
        }
        // Reserved sidecar capacity makes the physical promotion infallible;
        // no external provider or await separates it from queue commitment.
        if let Some(socket) = staged_scan {
            if index == self.sockets.len() {
                self.sockets.push(socket);
                self.completions.push(None);
            } else {
                self.sockets[index] = socket;
            }
        }
        self.push(finish, Origin::Effect)?;
        let completion = Publication {
            source: self.publication_source.clone(),
            sequence: self.next_effect,
        };
        let port = self.burst.as_mut().ok_or(Error::Stale)?;
        port.fence = Some(self.next_effect);
        port.report = Some(command.report(Outcome::Installed { scan, completion }));
        Ok(Some(Activity::Burst))
    }
}
