//! Incoming native flow admission, bounded TCP relays and original stop completion.
use crate::{
    Failure,
    settings::{duration, number},
};
use gnunet_config::Configuration;
use gnunet_dns_service_host::{
    Gateway,
    flow_relay::{RelayLimits, RelayPool, RelayPoolProgress, TcpUpstream},
};
use gnunet_native::dns_proxy::{
    Connection,
    provider::{AcceptedFlow, Controller, Event, Session, StopRequest},
};
use gnunet_program_host::reporting::Reporter;
use std::{
    task::{Context, Poll},
    time::Duration,
};

pub(crate) enum Progress {
    Activity,
    Stop,
}
pub(super) struct Resources {
    relays: RelayPool,
    upstream: gnunet_dns_service_host::upstream::ProviderUpstreamLimits,
}
impl Resources {
    pub(super) fn prepare(config: &Configuration) -> Result<Self, Failure> {
        let limits = RelayLimits {
            buffer_bytes: number(config, b"NATIVE_TCP_CHUNK_BYTES", 64 * 1024)?,
            open_timeout: duration(config, b"NATIVE_OPEN_TIMEOUT", Duration::from_secs(5))?,
            write_timeout: duration(config, b"NATIVE_TCP_WRITE_TIMEOUT", Duration::from_secs(30))?,
            idle_timeout: duration(config, b"NATIVE_TCP_IDLE_TIMEOUT", Duration::from_secs(300))?,
        };
        Ok(Self {
            relays: RelayPool::new(number(config, b"NATIVE_TCP_FLOWS", 32)?, limits)?,
            upstream: gnunet_dns_service_host::upstream::ProviderUpstreamLimits {
                readiness_timeout: limits.open_timeout,
                send_timeout: duration(
                    config,
                    b"NATIVE_UPSTREAM_SEND_TIMEOUT",
                    Duration::from_secs(30),
                )?,
            },
        })
    }
}

pub(crate) struct Runtime<'provider> {
    controller: &'provider mut Controller,
    session: Session,
    relays: RelayPool,
    stop: Option<StopRequest>,
    closing: bool,
    relays_done: bool,
    cursor: usize,
    upstream: gnunet_dns_service_host::upstream::ProviderUpstreamLimits,
}
impl<'provider> Runtime<'provider> {
    pub(super) fn new(
        controller: &'provider mut Controller,
        session: Session,
        resources: Resources,
    ) -> Self {
        Self {
            controller,
            session,
            relays: resources.relays,
            stop: None,
            closing: false,
            relays_done: false,
            cursor: 0,
            upstream: resources.upstream,
        }
    }
    pub(super) fn is_closing(&self) -> bool {
        self.closing
    }
    pub fn session(&self) -> Session {
        self.session.clone()
    }
    pub fn upstream_limits(&self) -> gnunet_dns_service_host::upstream::ProviderUpstreamLimits {
        self.upstream
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        gateway: &mut Gateway<'_>,
        reports: &Reporter,
    ) -> Poll<Result<Progress, Failure>> {
        if self.closing {
            return Poll::Ready(Ok(Progress::Stop));
        }
        for offset in 0..2 {
            let class = (self.cursor + offset) % 2;
            let result = if class == 0 {
                self.poll_incoming(cx, gateway, reports)
            } else {
                self.poll_relays(cx, reports)
                    .map(|()| Ok(Progress::Activity))
            };
            if result.is_ready() {
                self.cursor = (class + 1) % 2;
                return result;
            }
        }
        Poll::Pending
    }
    fn poll_incoming(
        &mut self,
        cx: &mut Context<'_>,
        gateway: &mut Gateway<'_>,
        reports: &Reporter,
    ) -> Poll<Result<Progress, Failure>> {
        match self.controller.poll_event(cx) {
            Poll::Ready(Ok(Event::Stop(mut stop))) => {
                stop.begin_drain();
                self.stop = Some(stop);
                self.close();
                Poll::Ready(Ok(Progress::Stop))
            }
            Poll::Ready(Ok(Event::Start(start))) => {
                start.reject();
                Poll::Ready(Err(
                    "DNS provider received a second start before stopping".into()
                ))
            }
            Poll::Ready(Ok(Event::Flow(flow))) => {
                self.admit(flow, gateway, reports);
                Poll::Ready(Ok(Progress::Activity))
            }
            Poll::Ready(Err(error)) => {
                self.close();
                Poll::Ready(Err(error.into()))
            }
            Poll::Pending => Poll::Pending,
        }
    }
    fn admit(&mut self, incoming: AcceptedFlow, gateway: &mut Gateway<'_>, reports: &Reporter) {
        let result: Result<(), Failure> = (|| {
            match incoming {
                AcceptedFlow::Udp(loan) => {
                    let flow = loan.adopt()?;
                    if let Err(refused) = gateway.admit_flow(flow) {
                        return Err(refused.error.into());
                    }
                }
                AcceptedFlow::Tcp(loan) => {
                    if !self.relays.has_capacity() {
                        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock).into());
                    }
                    let flow = loan.adopt()?;
                    let upstream = TcpUpstream::native(Connection::tcp_in_provider(
                        &flow,
                        self.session.lease()?,
                    )?);
                    if let Err(refused) = self.relays.admit(flow, upstream) {
                        return Err(refused.error.into());
                    }
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            reports.warning(
                "dns.provider.flow-refused",
                format_args!("dns original provider flow refused: {error}"),
            );
        }
    }
    fn poll_relays(&mut self, cx: &mut Context<'_>, reports: &Reporter) -> Poll<()> {
        match self.relays.poll(cx, None) {
            Poll::Ready(RelayPoolProgress::Finished { flow, report }) => {
                if report.first_error.is_some()
                    || report.retirement.as_ref().is_some_and(|r| r.has_failure())
                    || report
                        .upstream_retirement
                        .as_ref()
                        .is_some_and(|r| r.has_failure())
                {
                    reports.warning(
                        "dns.provider.tcp-retired",
                        format_args!("dns original TCP flow {flow:?}: {report:?}"),
                    );
                }
                Poll::Ready(())
            }
            Poll::Ready(RelayPoolProgress::Stopped) => {
                self.relays_done = true;
                Poll::Ready(())
            }
            Poll::Ready(RelayPoolProgress::Activity) => Poll::Ready(()),
            _ => Poll::Pending,
        }
    }
    pub fn close(&mut self) {
        if !self.closing {
            self.closing = true;
            if self.stop.is_none() {
                self.controller.shutdown_handle().request_shutdown();
            }
            self.relays.close();
        }
    }
    pub fn poll_cleanup(
        &mut self,
        cx: &mut Context<'_>,
        host_drained: bool,
        reports: &Reporter,
    ) -> Poll<Result<(), Failure>> {
        self.close();
        let mut activity = false;
        if self.stop.is_none() {
            match self.controller.poll_event(cx) {
                Poll::Ready(Ok(Event::Stop(mut stop))) => {
                    stop.begin_drain();
                    self.stop = Some(stop);
                }
                Poll::Ready(Ok(Event::Start(start))) => {
                    start.reject();
                    activity = true;
                }
                Poll::Ready(Ok(Event::Flow(flow))) => {
                    drop(flow);
                    activity = true;
                }
                _ => {}
            }
        }
        if !self.relays_done {
            activity |= self.poll_relays(cx, reports).is_ready();
        }
        if !host_drained || !self.relays_done {
            if activity {
                cx.waker().wake_by_ref();
            }
            return Poll::Pending;
        }
        match self.stop.as_mut() {
            Some(stop) => stop
                .poll_complete(cx)
                .map(|result| result.map_err(Into::into)),
            None => Poll::Ready(Ok(())),
        }
    }
}
