use crate::{Failure, settings::Settings};
use gnunet_bcd_host::{Event, Server, provider};
use gnunet_program_host::{policy::Level, reporting::Reporter};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_service_startup::{ControlReceiver, ParentControl};
use std::{
    future::poll_fn,
    io,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    net::TcpListener,
    signal::unix::{Signal, SignalKind, signal},
};
#[derive(Debug)]
struct Undrained(provider::Report);
impl std::fmt::Display for Undrained {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BCD terminal cleanup remains unconfirmed: {:?}", self.0)
    }
}
impl std::error::Error for Undrained {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.cleanup_error.as_deref().map(|e| e as _)
    }
}
struct Signals {
    parent: Option<ControlReceiver>,
    interrupt: Signal,
    terminate: Signal,
}
impl Signals {
    fn new(parent: Option<ParentControl>) -> io::Result<Self> {
        Ok(Self {
            parent: parent
                .map(|p| p.register().map_err(|e| e.error))
                .transpose()?,
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(parent) = &mut self.parent {
            match parent.poll_signal(cx) {
                Poll::Ready(Ok(Some(n)))
                    if i32::from(n) == libc_signal(false) || i32::from(n) == libc_signal(true) =>
                {
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Ok(Some(_))) => cx.waker().wake_by_ref(),
                Poll::Ready(Ok(None)) => self.parent = None,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {}
            }
        }
        for s in [&mut self.interrupt, &mut self.terminate] {
            match s.poll_recv(cx) {
                Poll::Ready(Some(())) => return Poll::Ready(Ok(())),
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::other("original BCD signal stream ended")));
                }
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }
}
fn libc_signal(term: bool) -> i32 {
    if term {
        SignalKind::terminate().as_raw_value()
    } else {
        SignalKind::interrupt().as_raw_value()
    }
}
pub async fn run(
    settings: Settings,
    clock: Arc<dyn RuntimeClock>,
    reporter: Reporter,
    parent: Option<ParentControl>,
) -> Result<(), Failure> {
    let mut signals = Signals::new(parent)?;
    // MHD's normal BCD entry explicitly requests dual stack. Do not depend on
    // a platform's IPV6_V6ONLY default, and never silently replace a selected
    // address after bind/listen failure.
    let socket = socket2::Socket::new(
        if settings.address.is_ipv6() {
            socket2::Domain::IPV6
        } else {
            socket2::Domain::IPV4
        },
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    if settings.address.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.bind(&settings.address.into())?;
    socket.listen(i32::try_from(settings.limits.connections)?)?;
    socket.set_nonblocking(true)?;
    let listener = TcpListener::from_std(socket.into())?;
    let actual = listener.local_addr()?;
    let mut server = Server::new(listener, settings.renderer, clock, settings.limits)?;
    reporter.message(
        Level::INFO,
        "bcd.ready",
        format_args!(
            "BCD actual HTTP listener {actual}; renderer tools are selected on generation requests"
        ),
    );
    let mut failure: Option<Failure> = None;
    loop {
        let next = poll_fn(|cx| {
            reporter.register(cx);
            if reporter.failed() {
                server.request_shutdown();
            }
            if !server.is_stopped() {
                match signals.poll(cx) {
                    Poll::Ready(Ok(())) => server.request_shutdown(),
                    Poll::Ready(Err(e)) => {
                        failure.get_or_insert_with(|| Box::new(e));
                        server.request_shutdown();
                    }
                    Poll::Pending => {}
                }
            }
            server.poll(cx)
        })
        .await;
        match next {
            Ok(Event::Stopped) => break,
            Ok(Event::RenderFailed { job, error }) => {
                reporter.message(
                    Level::ERROR,
                    "bcd.render.failed",
                    format_args!("job={job}: {error}; original report={:?}", error.report),
                );
                if server.report().undrained != 0 {
                    failure.get_or_insert_with(|| Box::new(error));
                }
            }
            Ok(Event::RetirementFailed { job, report }) => {
                reporter.message(
                    Level::ERROR,
                    "bcd.retirement.undrained",
                    format_args!("job={job}: original cleanup remains unconfirmed: {report:?}"),
                );
                failure.get_or_insert_with(|| Box::new(Undrained(report)));
            }
            Ok(event) => reporter.debug("bcd.progress", format_args!("{event:?}")),
            Err(error) => {
                failure.get_or_insert_with(|| Box::new(error));
                server.request_shutdown();
            }
        }
        if reporter.failed() {
            server.request_shutdown();
        }
        tokio::task::yield_now().await;
    }
    reporter.debug("bcd.closed", format_args!("{:?}", server.report()));
    match failure {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
