//! Numeric privileged binds and one bounded retained native CLIENT attempt.
use crate::{Cause, settings::Settings};
use gnunet_client_host::{ConnectionAttempt, EndpointSource};
use gnunet_program_host::reporting::Reporter;
use gnunet_service_runtime::connection::Connection;
use gnunet_udp_communicator_host::socket::DatagramSocket;
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Sleep;
pub(super) fn ipv6_supported() -> io::Result<bool> {
    match socket2::Socket::new(
        socket2::Domain::IPV6,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    ) {
        Ok(_socket) => Ok(true),
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(nix::libc::EAFNOSUPPORT | nix::libc::EPROTONOSUPPORT)
            ) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
pub(super) fn bind(settings: &Settings, reporter: &Reporter) -> Result<Vec<DatagramSocket>, Cause> {
    let mut sockets = Vec::new();
    sockets.try_reserve_exact(2)?;
    let mut failed = Vec::new();
    for address in settings.binds.iter().flatten() {
        match DatagramSocket::bind(*address) {
            Ok(socket) => sockets.push(socket),
            Err(error) => {
                reporter.warning("udp.bind.failed", format_args!("{address}: {error}"));
                failed.push(error);
            }
        }
    }
    if sockets.is_empty() {
        return Err(format!("all configured UDP binds failed: {failed:?}").into());
    }
    if reporter.failed() {
        return Err("selected UDP bind logger failed".into());
    }
    Ok(sockets)
}
pub(super) struct Dial {
    source: EndpointSource,
    attempt: Option<ConnectionAttempt>,
    retry: Option<Pin<Box<Sleep>>>,
    round: u64,
}
impl Dial {
    pub fn new(source: EndpointSource) -> Self {
        Self {
            source,
            attempt: None,
            retry: None,
            round: 0,
        }
    }
    /// A retired physical MQ starts one retained retry delay. Successful
    /// attachment never resets the failure round or creates another attempt.
    pub fn disconnected(&mut self) -> Result<(), Cause> {
        if self.attempt.is_some() || self.retry.is_some() {
            return Err("UDP CLIENT already reconnecting".into());
        }
        self.delay()
    }
    fn delay(&mut self) -> Result<(), Cause> {
        self.round = self
            .round
            .checked_add(1)
            .ok_or("UDP CLIENT retry overflow")?;
        let milliseconds = 10u64.saturating_mul(1u64 << self.round.min(10)).min(10_000);
        self.retry = Some(Box::pin(tokio::time::sleep(Duration::from_millis(
            milliseconds,
        ))));
        Ok(())
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        reporter: &Reporter,
    ) -> Poll<Result<Connection, Cause>> {
        if let Some(retry) = &mut self.retry {
            if retry.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.retry = None;
        }
        if self.attempt.is_none() {
            self.attempt = Some(self.source.resolve()?.attempt(self.round));
        }
        match Pin::new(
            self.attempt
                .as_mut()
                .ok_or("missing retained UDP CLIENT attempt")?,
        )
        .poll(cx)
        {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(connection)) => {
                self.attempt = None;
                Poll::Ready(Ok(connection))
            }
            Poll::Ready(Err(error)) => {
                self.attempt = None;
                reporter.warning("udp.transport.connect", format_args!("{error}"));
                self.delay()?;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}
