//! Original peer readiness, send/read completions and isolated group retirement.
use super::{Group, Provider, deadline, retire, retirement};
use crate::upstream::{Discard, Event, Flow, HostError};
use gnunet_types::Error;
use std::{
    io,
    task::{Context, Poll},
};
use tokio::time::Instant;
use zeroize::Zeroizing;

impl Provider {
    fn peer_failure(
        &mut self,
        group: &mut Group,
        index: usize,
        error: io::Error,
        callback: &mut impl FnMut(Event<'_>) -> Flow,
    ) -> Result<Option<Flow>, HostError> {
        let peer = group.peers[index].as_mut().ok_or(Error::Conflict)?;
        let destination = peer.connection.peer_addr()?;
        peer.connection.request_cancel();
        peer.retiring = true;
        peer.ready = false;
        let socket = group.socket;
        let event = if group.opened {
            let waiting = self.sends[socket.slot() as usize]
                .take_if(|send| send.socket == socket && send.destination == destination);
            if let Some(send) = waiting {
                self.core.sent(send.attempt)?;
                Event::Sent {
                    request: send.request,
                    socket,
                    destination,
                    result: Err(error),
                }
            } else {
                Event::PeerUnavailable {
                    socket,
                    destination,
                    error,
                }
            }
        } else {
            retire(group);
            self.core.socket_opened(socket, false)?;
            Event::SocketOpened {
                socket,
                result: Err(error),
            }
        };
        Ok(Some(callback(event)))
    }
    pub(super) fn poll_group(
        &mut self,
        group: &mut Group,
        cx: &mut Context<'_>,
        admit: bool,
        callback: &mut impl FnMut(Event<'_>) -> Flow,
    ) -> Result<Option<Flow>, HostError> {
        if group.retiring {
            retirement::drain(group, cx, &mut self.retirement);
            return Ok(None);
        }
        let capacity = group.peers.len();
        let cursor = group.cursor;
        for offset in 0..capacity {
            let index = (cursor + offset) % capacity;
            let Some(peer) = &mut group.peers[index] else {
                continue;
            };
            group.cursor = (index + 1) % capacity;
            if peer.retiring {
                retirement::poll_peer(&mut group.peers[index], cx, &mut self.retirement);
                continue;
            }
            if let Some(error) = peer.error.take() {
                return self.peer_failure(group, index, error, callback);
            }
            if peer.sending.is_some()
                && let Poll::Ready(Some(result)) = peer.connection.poll_send(cx)
            {
                if peer
                    .sending
                    .as_ref()
                    .and_then(|send| send.until)
                    .is_some_and(|until| Instant::now() >= until)
                {
                    return Ok(Some(callback(deadline::expire_send(peer, Some(result))?)));
                }
                let send = peer.sending.take().ok_or(Error::Conflict)?;
                return Ok(Some(callback(Event::Sent {
                    request: send.request,
                    socket: send.socket,
                    destination: send.destination,
                    result: result.map(|()| send.len),
                })));
            }
            if peer
                .sending
                .as_ref()
                .and_then(|send| send.until)
                .is_some_and(|until| Instant::now() >= until)
            {
                return Ok(Some(callback(deadline::expire_send(peer, None)?)));
            }
            if admit
                && peer.receiving
                && let Poll::Ready(Some(result)) = peer.connection.poll_receive(cx)
            {
                peer.receiving = false;
                let source = peer.connection.peer_addr()?;
                let received = match result {
                    Ok(received) => received,
                    Err(error) => {
                        return Ok(Some(callback(Event::ReceiveRejected {
                            socket: group.socket,
                            error,
                        })));
                    }
                };
                let (bytes, _end, error) = received.into_parts();
                let bytes = Zeroizing::new(bytes);
                peer.error = error;
                if bytes.is_empty() && peer.error.is_some() {
                    let error = peer.error.take().ok_or(Error::Conflict)?;
                    return self.peer_failure(group, index, error, callback);
                }
                let event = if bytes.len() > self.maximum {
                    Event::Discarded {
                        socket: group.socket,
                        source,
                        reason: Discard::Oversize {
                            limit: self.maximum,
                        },
                    }
                } else {
                    match self.core.receive(group.socket, source, &bytes) {
                        Ok(data) => Event::Datagram(data),
                        Err(reason) => Event::Discarded {
                            socket: group.socket,
                            source,
                            reason: Discard::Core(reason),
                        },
                    }
                };
                return Ok(Some(callback(event)));
            }
            match deadline::ready(peer, cx, self.limits.readiness_timeout) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(error) => return self.peer_failure(group, index, error, callback),
            }
            if admit
                && group.opened
                && !peer.receiving
                && self
                    .core
                    .readable_socket_at(group.socket.slot() as usize, group.socket.family())
                    == Some(group.socket)
            {
                match peer.connection.begin_receive(self.maximum) {
                    Ok(()) => {
                        peer.receiving = true;
                        cx.waker().wake_by_ref();
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(error) => return self.peer_failure(group, index, error, callback),
                }
            }
        }
        if !group.opened && group.peers.iter().flatten().all(|peer| peer.ready) {
            self.core.socket_opened(group.socket, true)?;
            group.opened = true;
            return Ok(Some(callback(Event::SocketOpened {
                socket: group.socket,
                result: Ok(()),
            })));
        }
        Ok(None)
    }
}
