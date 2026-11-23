//! Transparent UDP source for explicitly admitted Linux PREROUTING ingress.
use super::{
    OriginalInput, PendingOutput, ReplyOwner, Retirement, SourceEvent, TransparentPort, input,
};
use crate::{Upstream, core};
use gnunet_dnsstub_host::SocketReservations;
use gnunet_native::transparent_dns::{
    Listener, ListenerFamily, NetworkNamespace, ReplySocket,
    exclusion::{
        AdmittedDatagram, BypassMarks, ConfiguredIngresses, Ingresses, PendingReceive,
        UnqualifiedDatagram,
    },
};
use gnunet_service_runtime::{framing::OwnedFrame, readiness::RegisteredIo};
use std::{
    collections::VecDeque,
    io,
    num::NonZeroU32,
    os::fd::AsFd,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
};
use tokio::time::{Instant, Sleep};

mod output;
mod probe;
mod probes;
mod recovery;
mod topology;
use output::{Output, RegisteredReply};
use probes::{Lane, Probes};
use recovery::{Observed, Refresh, Restart};
use topology::IngressWatch;

const REPLY_SOCKETS: usize = 32;

/// Configured Linux interface names for transparent DNS capture.
#[derive(Debug)]
pub struct TransparentInterfaces(ConfiguredIngresses);

impl TransparentInterfaces {
    /// Validate a nonempty set of distinct names without opening native sockets.
    ///
    /// # Errors
    /// Reports invalid or duplicate names or allocation errors.
    pub fn new<'a>(names: impl IntoIterator<Item = &'a str>) -> io::Result<Self> {
        ConfiguredIngresses::new(names).map(Self)
    }

    /// Check whether a name was configured, independent of current link state.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.0.contains(name.as_bytes())
    }
}

/// Required Linux transparent ingress listener families.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum TransparentFamilies {
    /// Bind an IPv4 listener.
    Ipv4,
    /// Bind an IPv6-only listener.
    Ipv6,
    /// Bind both listeners before admitting capture.
    #[default]
    Dual,
}

/// Local socket retirement and original socket-mark restoration.
#[derive(Debug)]
pub struct TransparentRetirement {
    /// First native restoration failure for a retained upstream socket.
    pub mark_error: Option<io::Error>,
    /// Failure reported when joining the original link probe worker.
    pub probe_error: Option<io::Error>,
}

struct RegisteredInput {
    io: RegisteredIo<Listener>,
}

impl RegisteredInput {
    fn bind(
        ingress: &Ingresses,
        family: ListenerFamily,
        port: TransparentPort,
    ) -> io::Result<Self> {
        let listener = ingress.bind_listener(family, port)?;
        let io = RegisteredIo::from_descriptor(listener).map_err(|(_, error)| error)?;
        Ok(Self { io })
    }
}

enum Listeners {
    One(RegisteredInput),
    Dual([RegisteredInput; 2]),
}

impl Listeners {
    fn bind(
        ingress: &Ingresses,
        families: TransparentFamilies,
        port: TransparentPort,
    ) -> io::Result<Self> {
        let ipv4 = || RegisteredInput::bind(ingress, ListenerFamily::Ipv4, port);
        let ipv6 = || RegisteredInput::bind(ingress, ListenerFamily::Ipv6, port);
        Ok(match families {
            TransparentFamilies::Ipv4 => Self::One(ipv4()?),
            TransparentFamilies::Ipv6 => Self::One(ipv6()?),
            TransparentFamilies::Dual => Self::Dual([ipv4()?, ipv6()?]),
        })
    }

    fn as_slice(&self) -> &[RegisteredInput] {
        match self {
            Self::One(listener) => std::slice::from_ref(listener),
            Self::Dual(listeners) => listeners,
        }
    }
}

struct Open {
    listeners: Listeners,
    replies: VecDeque<RegisteredReply>,
    ingress: Ingresses,
    watch: IngressWatch,
    probes: Probes,
    bypass_mark: NonZeroU32,
}

impl Open {
    fn start(
        watch: IngressWatch,
        mut ingress: Ingresses,
        families: TransparentFamilies,
        port: TransparentPort,
        bypass_mark: NonZeroU32,
    ) -> io::Result<Self> {
        ingress.namespace().require(watch.namespace())?;
        if !ingress.has_active() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "no configured transparent DNS ingress",
            ));
        }
        let mut replies = VecDeque::new();
        replies
            .try_reserve_exact(REPLY_SOCKETS)
            .map_err(io::Error::other)?;
        let listeners = Listeners::bind(&ingress, families, port)?;
        let probes = Probes::launch(ingress.take_probe_worker()?)?;
        Ok(Self {
            listeners,
            replies,
            ingress,
            watch,
            probes,
            bypass_mark,
        })
    }

    fn poll_watch(
        &mut self,
        cx: &mut Context<'_>,
        configured: &ConfiguredIngresses,
    ) -> Poll<topology::Event> {
        if let Err(error) = self.probes.drive(cx, &mut self.ingress) {
            return Poll::Ready(topology::Event::Lost(error));
        }
        self.watch.poll(cx, &mut self.ingress, configured)
    }
}

struct Session {
    namespace: NetworkNamespace,
    marks: BypassMarks,
    reservations: SocketReservations,
    bypass_mark: NonZeroU32,
    families: TransparentFamilies,
    port: TransparentPort,
    interfaces: Arc<ConfiguredIngresses>,
}

struct Active<'id> {
    open: Open,
    output: Option<Output<'id>>,
    received: Option<UnqualifiedDatagram>,
    refresh: Option<Refresh>,
    refresh_requested: bool,
}

impl<'id> Active<'id> {
    fn new(open: Open) -> Self {
        Self {
            open,
            output: None,
            received: None,
            refresh: None,
            refresh_requested: false,
        }
    }
}

enum State<'id> {
    Active(Box<Active<'id>>),
    Detached {
        until: std::time::Instant,
        pending: Option<PendingOutput<'id>>,
        observed: Option<Box<Observed>>,
    },
    Rebinding {
        until: std::time::Instant,
        observed: Box<Observed>,
    },
    Retry {
        after: std::time::Instant,
        until: std::time::Instant,
    },
    Restarting(Restart),
    Validating {
        candidate: Box<Active<'id>>,
        until: std::time::Instant,
    },
    Closed,
}

pub(super) struct Transparent<'id> {
    state: State<'id>,
    session: Option<Session>,
    retiring_restart: Option<Restart>,
    retiring_probe: Option<probe::Worker>,
    read_buffer: Vec<u8>,
    read_cursor: usize,
    retirement: Option<TransparentRetirement>,
    timer: Pin<Box<Sleep>>,
}

impl<'id> Transparent<'id> {
    pub(super) async fn open(
        reservations: SocketReservations,
        families: TransparentFamilies,
        port: TransparentPort,
        bypass_mark: NonZeroU32,
        interfaces: TransparentInterfaces,
    ) -> io::Result<Self> {
        if reservations.sockets().len() == 0 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let interfaces = Arc::new(interfaces.0);
        let observed = Observed::startup(Arc::clone(&interfaces)).await?;
        let namespace = observed.ingress.namespace();
        let mut read_buffer = Vec::new();
        read_buffer
            .try_reserve_exact(core::MAX_DNS_BYTES)
            .map_err(io::Error::other)?;
        read_buffer.resize(core::MAX_DNS_BYTES, 0);

        let open = Open::start(
            observed.watch,
            observed.ingress,
            families,
            port,
            bypass_mark,
        )?;
        let marks = BypassMarks::apply(
            reservations.sockets().map(AsFd::as_fd),
            namespace,
            bypass_mark,
        )
        .map_err(io::Error::other)?;
        Ok(Self {
            state: State::Active(Box::new(Active::new(open))),
            session: Some(Session {
                namespace,
                marks,
                reservations,
                bypass_mark,
                families,
                port,
                interfaces,
            }),
            retiring_restart: None,
            retiring_probe: None,
            read_buffer,
            read_cursor: 0,
            retirement: None,
            timer: Box::pin(tokio::time::sleep_until(Instant::now())),
        })
    }

    pub(super) fn initialized(&self) -> bool {
        matches!(&self.state, State::Active(active) if active.open.watch.usable())
    }

    pub(super) fn writable(&self) -> bool {
        matches!(&self.state, State::Active(active) if active.open.watch.usable() && active.output.is_none())
    }

    pub(super) fn accepts(&self, endpoint: &AdmittedDatagram) -> bool {
        matches!(&self.state, State::Active(active)
            if active.open.watch.usable() && active.open.ingress.retains(endpoint.ingress()))
    }

    pub(super) fn matches(&self, stub: &Upstream) -> bool {
        self.session.as_ref().is_some_and(|session| {
            stub.standard_owner()
                .is_some_and(|owner| session.reservations.belongs_to(owner))
        })
    }

    pub(super) fn close(&mut self) {
        self.replace_and_retire(State::Closed);
        if let Some(mut session) = self.session.take() {
            self.retirement = Some(TransparentRetirement {
                mark_error: session.marks.restore().err().map(io::Error::other),
                probe_error: None,
            });
        }
    }

    pub(super) fn take_retirement(&mut self) -> Option<Retirement> {
        if self.retiring_restart.is_some() || self.retiring_probe.is_some() {
            return None;
        }
        self.retirement.take().map(Retirement::Transparent)
    }

    fn read(&mut self, cx: &mut Context<'_>) -> Poll<SourceEvent<'id>> {
        let State::Active(active) = &mut self.state else {
            return Poll::Pending;
        };
        let open = &mut active.open;
        if let Some(datagram) = &active.received {
            let receipt = ready!(open.probes.poll(cx, Lane::Input));
            let length = datagram.body_len();
            let Some(datagram) = active.received.take() else {
                return Poll::Pending;
            };
            let admitted = match open.ingress.admit(datagram, receipt) {
                Ok(admitted) => admitted,
                Err(error) => return Poll::Ready(SourceEvent::Refused(error.into())),
            };
            let input = OwnedFrame::copy_from(&self.read_buffer[..length])
                .map(|frame| {
                    OriginalInput::checked(frame, 0..length, ReplyOwner::Transparent(admitted))
                })
                .map_err(input::InputRefusal::from);
            return Poll::Ready(SourceEvent::Input(input));
        }
        if !open.probes.available(Lane::Input) {
            return Poll::Pending;
        }
        let listeners = open.listeners.as_slice();
        for offset in 0..listeners.len() {
            let index = (self.read_cursor + offset) % listeners.len();
            let listener = &listeners[index];
            let event = match listener.io.poll_read_on(cx, |listener| {
                open.ingress
                    .receive_unqualified(listener, &mut self.read_buffer)
            }) {
                Poll::Pending => continue,
                Poll::Ready(Err(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    // No datagram was received. Yield before retrying the same
                    // original socket, without retiring the source on a signal.
                    cx.waker().wake_by_ref();
                    continue;
                }
                Poll::Ready(Err(error)) => SourceEvent::Failed(error),
                Poll::Ready(Ok(PendingReceive::Refused(error))) => {
                    SourceEvent::Refused(error.into())
                }
                Poll::Ready(Ok(PendingReceive::Captured(datagram))) => {
                    self.read_cursor = (index + 1) % listeners.len();
                    match open
                        .ingress
                        .probe_input(&datagram)
                        .and_then(|request| open.probes.submit(Lane::Input, request))
                    {
                        Ok(()) => {
                            active.received = Some(datagram);
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        Err(error) => SourceEvent::Refused(error.into()),
                    }
                }
            };
            self.read_cursor = (index + 1) % listeners.len();
            return Poll::Ready(event);
        }
        Poll::Pending
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>, admit: bool) -> Poll<SourceEvent<'id>> {
        if let Poll::Ready(event) = self.poll_guard(cx) {
            return Poll::Ready(event);
        }
        if !matches!(&self.state, State::Active(active) if !active.open.watch.backlogged()) {
            return Poll::Pending;
        }
        if let Poll::Ready(event) = self.poll_output(cx) {
            return Poll::Ready(event);
        }
        if admit { self.read(cx) } else { Poll::Pending }
    }
}
