//! Fair reads and completion/retirement polling of the original SDK operations.
use super::{Entry, FlowRetirement, Flows, Phase, multicast, state::Disposition};
use crate::{
    Error,
    packet_source::{OriginalInput, PacketExposure, Retirement, SourceEvent, Write},
};
use gnunet_native::dns_proxy::{Read, ReadDatagram};
use gnunet_types::Error as Fault;
use std::{
    future::Future,
    io,
    task::{Context, Poll},
};
use tokio::time::Instant;

#[derive(Clone, Copy)]
enum GroupMode {
    Guard,
    Admit,
}

fn poll_group<'id>(
    entry: &mut Entry<'id>,
    report: Option<&mut FlowRetirement>,
    mode: GroupMode,
    cx: &mut Context<'_>,
) -> Poll<SourceEvent<'id>> {
    let Some(exchange) = &mut entry.multicast else {
        return Poll::Pending;
    };
    let progress = match mode {
        GroupMode::Guard => exchange.poll_guard(&mut entry.flow, cx),
        GroupMode::Admit => {
            exchange.poll_admission(&mut entry.flow, entry.state.pending().is_some(), cx)
        }
    };
    if exchange.retired() {
        entry.multicast = None;
    }
    progress.map(|progress| match progress {
        multicast::Progress::Activity => SourceEvent::Activity,
        multicast::Progress::Refused(error) => SourceEvent::Refused(error),
        multicast::Progress::CloseFlow => {
            entry.stop(Fault::Deadline, false);
            SourceEvent::Refused(Fault::Deadline.into())
        }
        multicast::Progress::Written { result, timely } => match result {
            Ok(()) => {
                if let Some(report) = report {
                    report.multicast_writes_accepted =
                        report.multicast_writes_accepted.saturating_add(1);
                    if !timely {
                        report.multicast_writes_late =
                            report.multicast_writes_late.saturating_add(1);
                    }
                }
                if !timely {
                    entry.stop(Fault::Deadline, false);
                }
                SourceEvent::Activity
            }
            Err(error) => {
                entry.stop(Fault::Closed, false);
                SourceEvent::Refused(error.into())
            }
        },
    })
}

impl<'id> Flows<'id> {
    fn poll_output(&mut self, slot: usize, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        let Some(entry) = &mut self.entries[slot] else {
            return Poll::Pending;
        };
        let Some(effect) = entry.state.pending().map(|output| output.effect) else {
            return Poll::Pending;
        };
        if entry.state.expire(Instant::now()) {
            entry.close_io();
        }
        let Poll::Ready(Some(result)) = entry.flow.poll_write(cx) else {
            return Poll::Pending;
        };
        let finished = match entry.state.finish(effect, result, Instant::now()) {
            Ok(finished) => finished,
            Err(error) => return Poll::Ready(SourceEvent::Failed(std::io::Error::other(error))),
        };
        match finished.disposition {
            Disposition::Written => Poll::Ready(SourceEvent::Written {
                effect,
                observation: Write::Flow,
            }),
            Disposition::Stopped { accepted, reason } => {
                entry.close_io();
                Poll::Ready(SourceEvent::OutputStopped {
                    effect,
                    exposure: if accepted {
                        PacketExposure::FlowWriteAccepted
                    } else {
                        PacketExposure::FlowWritePending
                    },
                    total: finished.output.bytes,
                    reason,
                })
            }
        }
    }
    pub fn poll_guard(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        let capacity = self.entries.len();
        for offset in 0..capacity {
            let slot = (self.cursor + offset) % capacity;
            if let Poll::Ready(event) = self.poll_output(slot, cx) {
                self.cursor = (slot + 1) % capacity;
                return Poll::Ready(event);
            }
            let Some(entry) = &mut self.entries[slot] else {
                continue;
            };
            if entry.state.expire(Instant::now()) {
                entry.close_io();
            }
            if let Poll::Ready(event) =
                poll_group(entry, self.report.as_mut(), GroupMode::Guard, cx)
            {
                self.cursor = (slot + 1) % capacity;
                return Poll::Ready(event);
            }
            if let Some(reason) = entry.state.notify_closed() {
                self.cursor = (slot + 1) % capacity;
                return Poll::Ready(SourceEvent::FlowStopped {
                    flow: entry.flow.id(),
                    reason: reason.into(),
                });
            }
            if entry.state.can_retire() {
                if let Err(error) = Self::drain(entry, cx) {
                    return Poll::Ready(SourceEvent::Failed(std::io::Error::other(error)));
                }
                if entry.multicast.is_none()
                    && let Poll::Ready(report) = entry.flow.poll_retirement(cx)
                {
                    self.record_retirement(report);
                    self.entries[slot] = None;
                    self.cursor = (slot + 1) % capacity;
                    return Poll::Ready(SourceEvent::Activity);
                }
            }
        }
        let wake = self
            .entries
            .iter()
            .flatten()
            .flat_map(|entry| {
                [
                    entry.state.deadline(),
                    entry
                        .multicast
                        .as_ref()
                        .and_then(multicast::Exchange::deadline),
                ]
            })
            .flatten()
            .min();
        if let Some(wake) = wake {
            self.timer.as_mut().reset(wake);
            if self.timer.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        accepts_new_input: bool,
    ) -> Poll<SourceEvent<'id>> {
        if self.closing {
            return self.poll_retirement(cx).map(SourceEvent::Retired);
        }
        if let Poll::Ready(event) = self.poll_guard(cx) {
            return Poll::Ready(event);
        }
        let capacity = self.entries.len();
        for offset in 0..capacity {
            let slot = (self.cursor + offset) % capacity;
            let Some(entry) = &mut self.entries[slot] else {
                continue;
            };
            match entry.state.phase() {
                Phase::Closing { .. } => continue,
                Phase::Opening { .. } => match entry.flow.poll_open(cx) {
                    Poll::Ready(Some(Ok(()))) => {
                        entry.state.opened();
                        self.cursor = (slot + 1) % capacity;
                        return Poll::Ready(SourceEvent::Activity);
                    }
                    Poll::Ready(Some(Err(error))) => {
                        entry.stop(Fault::Closed, false);
                        self.failure(error);
                        return Poll::Ready(SourceEvent::Activity);
                    }
                    _ => continue,
                },
                Phase::Open => {}
            }
            // Existing group work has its own slot and lifetime. Core span
            // capacity controls new reads and inputs, not these operations.
            if let Poll::Ready(event) =
                poll_group(entry, self.report.as_mut(), GroupMode::Admit, cx)
            {
                self.cursor = (slot + 1) % capacity;
                return Poll::Ready(event);
            }
            if !entry.buffered.is_empty() {
                if accepts_new_input && let Some(datagram) = entry.take_read() {
                    self.cursor = (slot + 1) % capacity;
                    return Poll::Ready(match datagram {
                        ReadDatagram::Unicast(datagram) => {
                            SourceEvent::Input(OriginalInput::flow(datagram))
                        }
                        ReadDatagram::Multicast(request) => {
                            let started = self
                                .limits
                                .multicast_timeout
                                .ok_or_else(|| Error::Io(io::ErrorKind::Unsupported.into()))
                                .and_then(|lifetime| {
                                    multicast::Exchange::start(&mut entry.flow, request, lifetime)
                                });
                            match started {
                                Ok(exchange) => {
                                    entry.multicast = Some(exchange);
                                    SourceEvent::Activity
                                }
                                Err(error) => {
                                    if let Some(report) = &mut self.report {
                                        report.refused = report.refused.saturating_add(1);
                                    }
                                    SourceEvent::Refused(error)
                                }
                            }
                        }
                    });
                }
                continue;
            }
            if !entry.reading {
                if !accepts_new_input {
                    continue;
                }
                let read = if self.limits.multicast_timeout.is_some() {
                    entry.flow.begin_read_with_multicast(self.limits.read)
                } else {
                    entry.flow.begin_read(self.limits.read)
                };
                match read {
                    Ok(()) => entry.reading = true,
                    Err(error) => {
                        entry.stop(Fault::Closed, false);
                        self.failure(error);
                        return Poll::Ready(SourceEvent::Activity);
                    }
                }
            }
            match entry.flow.poll_read(cx) {
                Poll::Ready(Some(Ok(Read::Datagrams(batch)))) => {
                    entry.reading = false;
                    let (datagrams, refused, error) = batch.into_parts();
                    entry.buffered = datagrams.into();
                    if let Some(report) = &mut self.report {
                        report.refused = report.refused.saturating_add(refused as u64);
                    }
                    self.cursor = (slot + 1) % capacity;
                    return Poll::Ready(match error {
                        Some(error) => SourceEvent::Refused(error.into()),
                        None => SourceEvent::Activity,
                    });
                }
                Poll::Ready(Some(Ok(Read::End))) => {
                    entry.stop(Fault::Closed, false);
                    return Poll::Ready(SourceEvent::Activity);
                }
                Poll::Ready(Some(Err(error))) => {
                    entry.stop(Fault::Closed, false);
                    self.failure(error);
                    return Poll::Ready(SourceEvent::Activity);
                }
                _ => {}
            }
        }
        Poll::Pending
    }
    fn drain(entry: &mut Entry<'id>, cx: &mut Context<'_>) -> Result<(), Fault> {
        let _open = entry.flow.poll_open(cx);
        let _read = entry.flow.poll_read(cx);
        // The result is consumed only after its callback and final argument
        // disposal. Shutdown never turns late acceptance into Written.
        if let Some(effect) = entry.state.pending().map(|output| output.effect)
            && let Poll::Ready(Some(result)) = entry.flow.poll_write(cx)
        {
            let _finished = entry.state.finish(effect, result, Instant::now())?;
        }
        Ok(())
    }
    fn record_retirement(&mut self, receipt: gnunet_native::dns_proxy::Retirement) {
        if let Some(report) = &mut self.report {
            report.retired = report.retired.saturating_add(1);
            if receipt.has_failure() {
                report.retirement_failures = report.retirement_failures.saturating_add(1);
                if report.first_retirement.is_none() {
                    report.first_retirement = Some(receipt);
                }
            }
        }
    }
    pub fn poll_retirement(&mut self, cx: &mut Context<'_>) -> Poll<Retirement> {
        if !self.closing {
            return Poll::Pending;
        }
        for slot in 0..self.entries.len() {
            let Some(entry) = &mut self.entries[slot] else {
                continue;
            };
            if poll_group(entry, self.report.as_mut(), GroupMode::Guard, cx).is_ready() {
                cx.waker().wake_by_ref();
            }
            if let Err(error) = Self::drain(entry, cx) {
                self.failure(std::io::Error::other(error));
                continue;
            }
            if entry.state.can_retire()
                && entry.multicast.is_none()
                && let Poll::Ready(report) = entry.flow.poll_retirement(cx)
            {
                self.record_retirement(report);
                self.entries[slot] = None;
            }
        }
        if self.entries.iter().any(Option::is_some) {
            return Poll::Pending;
        }
        self.report.take().map_or(Poll::Pending, |report| {
            Poll::Ready(Retirement::Flows(report))
        })
    }
}
