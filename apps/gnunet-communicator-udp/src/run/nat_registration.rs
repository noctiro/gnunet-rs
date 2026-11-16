//! Independent NAT registration intents on the original shared selector and clock.
use super::*;

#[expect(
    clippy::large_enum_variant,
    reason = "Keep the bounded original registration inline; waiting holds no second registration or heap owner"
)]
enum Phase<'instance> {
    Observing(nat::Registration<'instance>),
    Waiting(std::pin::Pin<Box<Sleep>>),
    Closed,
}
pub(super) enum Retirement {
    Recovering,
    Terminal,
}
pub(super) struct Observer<'instance> {
    instance: &'instance nat::Instance,
    source: EndpointSource,
    bound: Vec<std::net::SocketAddr>,
    phase: Phase<'instance>,
    round: u64,
}
impl<'instance> Observer<'instance> {
    pub fn new(
        instance: &'instance nat::Instance,
        source: EndpointSource,
        bound: &[std::net::SocketAddr],
    ) -> Result<Self, Cause> {
        let mut bindings = Vec::new();
        bindings.try_reserve_exact(bound.len())?;
        bindings.extend_from_slice(bound);
        let active = registration(instance, source.duplicate()?, &bindings)?;
        Ok(Self {
            instance,
            source,
            bound: bindings,
            phase: Phase::Observing(active),
            round: 0,
        })
    }
    pub fn registration(&self) -> Result<&nat::Registration<'instance>, gnunet_types::Error> {
        match &self.phase {
            Phase::Observing(registration) => Ok(registration),
            Phase::Waiting(_) | Phase::Closed => Err(gnunet_types::Error::NotReady),
        }
    }
    pub fn registration_mut(
        &mut self,
    ) -> Result<&mut nat::Registration<'instance>, gnunet_types::Error> {
        match &mut self.phase {
            Phase::Observing(registration) => Ok(registration),
            Phase::Waiting(_) | Phase::Closed => Err(gnunet_types::Error::NotReady),
        }
    }
    /// Handle only the actual current source's End after its claims were retired.
    /// A retry is a new REGISTER intent with new allocation/epoch/address IDs;
    /// the old notification, request cursors and writes are never replayed.
    pub fn retired(
        &mut self,
        end: &nat::End<'instance>,
    ) -> Result<Retirement, gnunet_types::Error> {
        if self.registration()?.session() != end.source.session {
            return Err(gnunet_types::Error::StaleGeneration);
        }
        if !recoverable(&end.source.cause) {
            return Ok(Retirement::Terminal);
        }
        let round = self
            .round
            .checked_add(1)
            .ok_or(gnunet_types::Error::Overflow)?;
        let delay = Duration::from_millis(
            100_u64
                .saturating_mul(1 << round.saturating_sub(1).min(7))
                .min(10_000),
        );
        self.phase = Phase::Waiting(Box::pin(tokio::time::sleep(delay)));
        self.round = round;
        Ok(Retirement::Recovering)
    }
    /// Original native guards precede all outer clock/interface providers.
    /// Backoff cannot construct a new registration or sample a clock here.
    pub fn poll_native_guard(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<tokio::time::Instant>,
    ) -> Poll<Result<nat::Progress<'instance>, nat::Error>> {
        match &mut self.phase {
            Phase::Observing(registration) => registration.poll_native_guard(cx, wait),
            Phase::Waiting(_) | Phase::Closed => Poll::Pending,
        }
    }
    pub fn poll(
        &mut self,
        cx: &mut Context<'_>,
        wait: Option<tokio::time::Instant>,
    ) -> Poll<Result<nat::Progress<'instance>, Cause>> {
        if let Phase::Waiting(alarm) = &mut self.phase {
            if alarm.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            let registration = registration(self.instance, self.source.duplicate()?, &self.bound)?;
            self.phase = Phase::Observing(registration);
        }
        match &mut self.phase {
            Phase::Observing(registration) => registration
                .poll(cx, wait)
                .map_err(|error| Box::new(error) as Cause),
            Phase::Waiting(_) | Phase::Closed => Poll::Pending,
        }
    }
    pub fn close(&mut self) -> Option<nat::End<'instance>> {
        match std::mem::replace(&mut self.phase, Phase::Closed) {
            Phase::Observing(mut registration) => registration.close(),
            Phase::Waiting(_) | Phase::Closed => None,
        }
    }
}
fn remote_fault(error: gnunet_types::Error) -> bool {
    matches!(
        error,
        gnunet_types::Error::Malformed
            | gnunet_types::Error::Truncated
            | gnunet_types::Error::InvalidInput
            | gnunet_types::Error::Unsupported
            | gnunet_types::Error::TooLarge
            | gnunet_types::Error::Capacity
    )
}
fn ports(error: &gnunet_client_host::ConnectError) -> bool {
    match error {
        gnunet_client_host::ConnectError::Io(error) => error.kind() != io::ErrorKind::OutOfMemory,
        gnunet_client_host::ConnectError::Protocol(error) => remote_fault(*error),
        gnunet_client_host::ConnectError::Configuration(_) => false,
    }
}
fn recoverable(cause: &nat::Cause) -> bool {
    match cause {
        nat::Cause::Eof
        | nat::Cause::Deadline
        | nat::Cause::WriteDeadline
        | nat::Cause::FirstInputDeadline
        | nat::Cause::InputDeadline => true,
        nat::Cause::Io(error) => error.kind() != io::ErrorKind::OutOfMemory,
        nat::Cause::Protocol(error) => remote_fault(*error),
        nat::Cause::Ports(error) => ports(error),
        nat::Cause::Error(nat::Error::Protocol(error)) => remote_fault(*error),
        nat::Cause::Error(nat::Error::Ports(error)) => ports(error),
        nat::Cause::Closed
        | nat::Cause::Cancelled
        | nat::Cause::Clock(_)
        | nat::Cause::Error(nat::Error::Clock(_) | nat::Error::Configuration(_)) => false,
    }
}
pub(super) fn ended<'instance>(
    observer: &mut Observer<'instance>,
    end: nat::End<'instance>,
    reporter: &Reporter,
) -> Result<(), Cause> {
    match observer.retired(&end)? {
        Retirement::Recovering => {
            reporter.warning(
                "udp.nat.lost",
                format_args!("{}; fresh registration scheduled", loss(end)),
            );
            Ok(())
        }
        Retirement::Terminal => Err(loss(end)),
    }
}

fn registration<'id>(
    instance: &'id nat::Instance,
    source: EndpointSource,
    bound: &[std::net::SocketAddr],
) -> Result<nat::Registration<'id>, Cause> {
    let now = source.clock().sample()?.now.as_micros();
    let profile = nat::native_profile()?;
    let mut scratch = [0; 56];
    let mut writer = nat::ipc::AddressWriter::new(&mut scratch, profile);
    for address in bound {
        writer.push(match address {
            std::net::SocketAddr::V4(a) => nat::ipc::Address::V4 {
                ip: a.ip().octets(),
                port: a.port(),
            },
            std::net::SocketAddr::V6(a) => nat::ipc::Address::V6 {
                ip: a.ip().octets(),
                port: a.port(),
                flow: a.flowinfo(),
                scope: a.scope_id(),
            },
        })?;
    }
    let request = nat::RegistrationRequest {
        flags: nat::ipc::ADDRESSES | nat::ipc::REVERSAL,
        protocol: 17,
        addresses: writer.addresses(),
        section: b"communicator-udp",
    };
    let until = now
        .checked_add(30_000_000)
        .filter(|n| *n != u64::MAX)
        .ok_or("NAT registration time overflow")?;
    Ok(nat::Registration::new(
        instance,
        source,
        request,
        nat::Profiles::same(profile),
        nat::Deadlines {
            send_until: until,
            first_input_until: None,
            until: u64::MAX,
        },
        nat::Limits::default(),
    )?)
}
#[derive(Debug)]
struct NatLost {
    cause: nat::Cause,
    notification: bool,
    addresses: usize,
    pending_writes: usize,
}
impl std::fmt::Display for NatLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "original NAT source ended: {:?}; held callback={}, addresses={}, pending writes={}",
            self.cause, self.notification, self.addresses, self.pending_writes
        )
    }
}
impl std::error::Error for NatLost {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            nat::Cause::Io(error) => Some(error),
            nat::Cause::Ports(error) => Some(error),
            nat::Cause::Error(error) => Some(error),
            nat::Cause::Clock(error) | nat::Cause::Protocol(error) => Some(error),
            _ => None,
        }
    }
}
pub(super) fn loss(end: nat::End<'_>) -> Cause {
    Box::new(NatLost {
        notification: end.notification.is_some(),
        addresses: end.addresses.len(),
        pending_writes: end.source.writes.len(),
        cause: end.source.cause,
    })
}

#[cfg(test)]
mod tests;
