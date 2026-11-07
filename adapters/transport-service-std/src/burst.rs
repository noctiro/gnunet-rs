//! Real HELLO-cache→original burst demand→standard1253/native lifetime port.
//! No new MQ/worker/socket/Resolver/task, no authenticated route from a hint.
use crate::{Failure, discovery, time::Clock};
use gnunet_transport::{
    Times,
    burst::{self, Id, Stage},
};
use gnunet_transport_host::Server;
use gnunet_transport_host::discovery::VisitControl;
use gnunet_types::Error;
use gnunet_wire::official::AbsoluteTime;
use std::{
    fmt::{self, Write},
    future::Future,
    num::NonZeroUsize,
    pin::Pin,
    str::FromStr,
    task::Context,
};
use tokio::time::{Instant, Sleep};
struct Original {
    id: Id,
    hard: Instant,
    cursor: usize,
}
/// One bounded actual port. Original native targets use the process's shared
/// fixed Clock anchor, not a newly computed duration on each poll/retry.
#[derive(Default)]
pub struct Port {
    original: Option<Original>,
    alarm: Option<Pin<Box<Sleep>>>,
}
impl Port {
    /// Clear only after the old Server's MQs physically retired. This grants no
    /// callback, remote completion or reusable old Engine/communicator lease.
    pub fn after_physical_retirement(&mut self) {
        self.original = None;
        self.alarm = None;
    }
    /// Check/register native bounds before any canonical sampling or IO. The
    /// Server also enforces the exact original command bound before its own IO.
    pub fn native_guard(
        &mut self,
        server: &mut Server,
        clock: &Clock,
        cx: &mut Context<'_>,
    ) -> Result<bool, Failure> {
        let Some(request) = server.burst_request().cloned() else {
            self.original = None;
            self.alarm = None;
            return Ok(false);
        };
        let mut changed = false;
        if self
            .original
            .as_ref()
            .is_none_or(|old| old.id != request.id)
        {
            self.original = Some(Original {
                id: request.id.clone(),
                hard: clock.native_bound(request.until)?,
                cursor: 0,
            });
            self.alarm = None;
            changed = true;
        }
        let original = self.original.as_ref().ok_or(Error::Stale)?;
        let hard = original.hard;
        if request.selected.is_some() {
            let command = request.command_until.ok_or(Error::Stale)?;
            let bound = hard.min(clock.native_bound(command)?);
            server.arm_burst(&request.id, bound)?;
            return Ok(changed);
        }
        if Instant::now() >= hard {
            server.cancel_burst(&request.id, burst::End::Deadline)?;
            self.original = None;
            self.alarm = None;
            return Ok(true);
        }
        let due = match request.starts {
            Some(at) => clock.native_bound(at)?.min(hard),
            None => hard,
        };
        // A passed delay waiting for a communicator/capacity does not cause a
        // self-waking sleep at a past timestamp. Existing IO/ticks drive retry.
        let due = if due > Instant::now() { due } else { hard };
        let alarm = self
            .alarm
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(due)));
        alarm.as_mut().reset(due);
        let _ready = alarm.as_mut().poll(cx);
        Ok(changed)
    }
    /// Drive after the Owner's other pure Engine calls in this poll. A fresh
    /// actual sample used for candidate admission cannot regress later calls.
    pub fn advance(
        &mut self,
        server: &mut Server,
        source: &mut discovery::Provider<'_>,
        clock: &mut Clock,
        times: Times,
        cx: &mut Context<'_>,
    ) -> Result<(bool, Option<burst::Outcome>), Failure> {
        let mut changed = self.native_guard(server, clock, cx)?;
        if !server.persistence_pending() {
            changed |= server.drive_burst(times)?;
        }
        changed |= self.native_guard(server, clock, cx)?;
        if let Some(outcome) = server.take_burst_outcome() {
            return Ok((true, Some(outcome)));
        }
        let Some(request) = server.burst_request().cloned() else {
            return Ok((changed, None));
        };
        let mut now = times;
        if request.stage == Stage::Lookup && !server.persistence_pending() {
            let original = self.original.as_mut().ok_or(Error::Stale)?;
            let mut hint = None;
            let visit = match source.visit_hello(
                request.peer,
                times.absolute().as_micros(),
                original.cursor,
                NonZeroUsize::new(16).ok_or(Error::InvalidInput)?,
                &mut |candidate| {
                    if hint.is_some() {
                        return Ok(VisitControl::Pause);
                    }
                    if !matches!(candidate.provenance, discovery::Provenance::Hello { .. }) {
                        return Err(Error::Stale);
                    }
                    if let Some(ip) = portless(candidate.address) {
                        hint = Some((ip, candidate.expires));
                    }
                    Ok(VisitControl::Continue)
                },
            ) {
                Ok(visit) => visit,
                Err(Error::Capacity | Error::WouldBlock | Error::NotReady) => {
                    return Ok((changed, None));
                }
                Err(error) => return Err(error.into()),
            };
            changed |= original.cursor != visit.cursor;
            original.cursor = visit.cursor;
            if let Some((hint, expiry)) = hint {
                // Check the fixed original native bound again after all real
                // source/cache work, before calling the logical clock port.
                if Instant::now() >= original.hard {
                    server.cancel_burst(&request.id, burst::End::Deadline)?;
                    return Ok((true, server.take_burst_outcome()));
                }
                now = clock.sample()?;
                if Instant::now() >= original.hard {
                    server.cancel_burst(&request.id, burst::End::Deadline)?;
                    return Ok((true, server.take_burst_outcome()));
                }
                match server.burst_candidate(
                    &request.id,
                    hint.bytes(),
                    AbsoluteTime::from_micros(expiry),
                    now,
                ) {
                    Ok(()) => changed = true,
                    Err(Error::Stale) => {}
                    Err(Error::Deadline) => {
                        if server
                            .burst_request()
                            .is_some_and(|current| current.id == request.id)
                        {
                            server.cancel_burst(&request.id, burst::End::Deadline)?;
                        }
                    }
                    Err(e) => return Err(e.into()),
                }
            } else if visit.finished {
                server.cancel_burst(&request.id, burst::End::NoAddress)?;
                changed = true;
            }
        }
        if !server.persistence_pending() {
            changed |= server.drive_burst(now)?;
        }
        changed |= self.native_guard(server, clock, cx)?;
        Ok((changed, server.take_burst_outcome()))
    }
}
struct IpText {
    bytes: [u8; 45],
    used: usize,
}
impl IpText {
    fn bytes(&self) -> &[u8] {
        &self.bytes[..self.used]
    }
}
impl Write for IpText {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let end = self.used.checked_add(text.len()).ok_or(fmt::Error)?;
        let target = self.bytes.get_mut(self.used..end).ok_or(fmt::Error)?;
        target.copy_from_slice(text.as_bytes());
        self.used = end;
        Ok(())
    }
}
fn portless(native: &[u8]) -> Option<IpText> {
    let split = native.iter().position(|b| *b == b'-')?;
    if split == 0 {
        return None;
    }
    let body = std::str::from_utf8(native.get(split + 1..)?).ok()?;
    // Only a literal IP can be a traversal hint here; this does not impose a
    // UTF-8 requirement on general opaque communicator/cache addresses.
    let ip = if let Ok(ip) = std::net::IpAddr::from_str(body) {
        ip
    } else {
        let socket = std::net::SocketAddr::from_str(body).ok()?;
        if matches!(socket,std::net::SocketAddr::V6(v6) if v6.scope_id()!=0) {
            return None;
        }
        socket.ip()
    };
    let mut out = IpText {
        bytes: [0; 45],
        used: 0,
    };
    write!(&mut out, "{ip}").ok()?;
    Some(out)
}
