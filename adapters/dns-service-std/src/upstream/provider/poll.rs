//! Fair core effects, fixed-peer native sends and unchanged callback correlation.
use super::{Provider, connect, group_index};
use crate::upstream::{Event, Flow, HostError, Progress};
use gnunet_types::Error;
use std::{
    future::Future,
    io,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

impl Provider {
    fn poll_sends(
        &mut self,
        cx: &mut Context<'_>,
        callback: &mut impl FnMut(Event<'_>) -> Flow,
    ) -> Result<Option<Flow>, HostError> {
        for slot in 0..self.sends.len() {
            let Some(mut send) = self.sends[slot].take() else {
                continue;
            };
            if !self.core.owns_request(send.request) || !self.core.owns_socket(send.socket) {
                continue;
            }
            let Some(group) = self.groups[group_index(send.socket)]
                .as_mut()
                .filter(|group| group.socket == send.socket && group.opened && !group.retiring)
            else {
                self.sends[slot] = Some(send);
                continue;
            };
            let mut existing = None;
            for (index, peer) in group.peers.iter().enumerate() {
                if let Some(peer) = peer
                    && peer.connection.peer_addr()? == send.destination
                {
                    existing = Some(index);
                    break;
                }
            }
            let peer_slot = match existing {
                Some(slot) => slot,
                None => {
                    let index = group
                        .peers
                        .iter()
                        .position(Option::is_none)
                        .ok_or(Error::Capacity)?;
                    let created = connect(
                        &self.session,
                        send.destination,
                        self.limits.readiness_timeout,
                    );
                    match created {
                        Ok(peer) => {
                            group.peers[index] = Some(peer);
                            cx.waker().wake_by_ref();
                        }
                        Err(error) => {
                            self.core.sent(send.attempt)?;
                            return Ok(Some(callback(Event::Sent {
                                request: send.request,
                                socket: send.socket,
                                destination: send.destination,
                                result: Err(error),
                            })));
                        }
                    }
                    index
                }
            };
            let peer = group.peers[peer_slot].as_mut().ok_or(Error::Conflict)?;
            if peer.retiring || peer.sending.is_some() {
                self.core.sent(send.attempt)?;
                return Ok(Some(callback(Event::Sent {
                    request: send.request,
                    socket: send.socket,
                    destination: send.destination,
                    result: Err(io::ErrorKind::WouldBlock.into()),
                })));
            }
            if !peer.ready {
                self.sends[slot] = Some(send);
                continue;
            }
            let bytes = self.core.query(send.request)?;
            if bytes.len() != send.len {
                return Err(Error::Conflict.into());
            }
            send.until = Some(
                Instant::now()
                    .checked_add(self.limits.send_timeout)
                    .ok_or(Error::Overflow)?,
            );
            let result = peer.connection.begin_send(bytes);
            self.core.sent(send.attempt)?;
            match result {
                Ok(()) => {
                    peer.sending = Some(send);
                    cx.waker().wake_by_ref();
                }
                Err(error) => {
                    return Ok(Some(callback(Event::Sent {
                        request: send.request,
                        socket: send.socket,
                        destination: send.destination,
                        result: Err(error),
                    })));
                }
            }
        }
        Ok(None)
    }
    pub(super) fn poll_groups(
        &mut self,
        cx: &mut Context<'_>,
        admit: bool,
        callback: &mut impl FnMut(Event<'_>) -> Flow,
    ) -> Result<Option<Flow>, HostError> {
        self.poll_retired(cx);
        let capacity = self.groups.len();
        for offset in 0..capacity {
            let index = (self.cursor + offset) % capacity;
            if let Some(mut group) = self.groups[index].take() {
                let result = self.poll_group(&mut group, cx, admit, callback);
                let retired = group.retiring && group.peers.iter().all(Option::is_none);
                if !retired {
                    self.groups[index] = Some(group);
                }
                let result = result?;
                if result.is_some() {
                    self.cursor = (index + 1) % capacity;
                    return Ok(result);
                }
            }
            if admit && let Some(opening) = self.openings[index] {
                let flow = self.install(opening, callback)?;
                if self.openings[index].is_none() {
                    cx.waker().wake_by_ref();
                }
                if flow.is_some() {
                    self.cursor = (index + 1) % capacity;
                    return Ok(flow);
                }
            }
        }
        Ok(None)
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        deadline: Option<Instant>,
        callback: &mut impl FnMut(Event<'_>) -> Flow,
    ) -> Poll<Result<Progress, HostError>> {
        for _ in 0..32 {
            if self.core.is_stopped() {
                return Poll::Ready(Ok(Progress::Stopped));
            }
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                return Poll::Ready(Ok(Progress::WaitDeadline));
            }
            let result = if self.action_first {
                match self.next_action(callback)? {
                    Some(flow) => Some(flow),
                    None => match self.poll_sends(cx, callback)? {
                        Some(flow) => Some(flow),
                        None => self.poll_groups(cx, true, callback)?,
                    },
                }
            } else {
                match self.poll_groups(cx, true, callback)? {
                    Some(flow) => Some(flow),
                    None => match self.next_action(callback)? {
                        Some(flow) => Some(flow),
                        None => self.poll_sends(cx, callback)?,
                    },
                }
            };
            if let Some(flow) = result {
                self.action_first = !self.action_first;
                if flow == Flow::Return {
                    return Poll::Ready(Ok(Progress::Activity));
                }
                continue;
            }
            let wake = self
                .core
                .next_wakeup()
                .map(|at| {
                    self.epoch
                        .checked_add(Duration::from_micros(at.0))
                        .ok_or(Error::Overflow)
                })
                .transpose()?
                .into_iter()
                .chain(self.native_deadline())
                .chain(deadline)
                .min();
            if let Some(wake) = wake {
                self.timer.as_mut().reset(wake);
                if self.timer.as_mut().poll(cx).is_ready() {
                    continue;
                }
            }
            return Poll::Pending;
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }
}
