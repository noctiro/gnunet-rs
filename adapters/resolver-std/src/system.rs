//! Bounded native policy lookup owners and their original core generations.
use gnunet_client::resolver::Family;
use gnunet_dns::{Idna, MAX_NAME_LENGTH};
use gnunet_resolver_service_core::owner::{LookupId, SystemAnswer, SystemQuery, SystemQuestion};
use gnunet_types::{Error, MonoInstant};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, LazyLock},
    task::{Context, Poll},
};
use tokio::sync::Semaphore;

#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd"
))]
mod nss;
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd"
))]
use nss as native;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
use macos as native;
#[cfg(windows)]
mod windows;
#[cfg(windows)]
use windows as native;

#[cfg(not(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd",
    target_os = "macos",
    windows
)))]
mod native {
    use super::{Answer, Context, Poll, Question, io};
    use tokio::sync::OwnedSemaphorePermit;

    pub(super) enum Request {}

    pub(super) fn start(_: Question<'_>, _: usize, _: OwnedSemaphorePermit) -> io::Result<Request> {
        Err(io::ErrorKind::Unsupported.into())
    }

    impl Request {
        pub(super) fn poll(&mut self, _: &mut Context<'_>) -> Poll<io::Result<Vec<Answer>>> {
            match *self {}
        }
    }
}

/// Original operating-system resolver policy for an ordinary node.
pub struct SystemDns {
    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd"
    ))]
    worker: native::Worker,
    #[cfg(not(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd"
    )))]
    _private: (),
}

impl SystemDns {
    /// Select the system resolver on macOS or Windows.
    #[cfg(not(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd"
    )))]
    pub fn new() -> io::Result<Self> {
        if cfg!(any(target_os = "macos", windows)) {
            Ok(Self { _private: () })
        } else {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "native Resolver DNS policy is unavailable on this target",
            ))
        }
    }

    /// Select the Unix name service through a trusted absolute worker executable.
    /// The executable dispatches [`SYSTEM_DNS_WORKER_ARGUMENT`] before starting
    /// its application runtime. The worker supervisor exclusively waits for
    /// its children. The caller keeps SIGCHLD wait semantics enabled.
    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd"
    ))]
    pub fn for_worker(executable: std::path::PathBuf) -> io::Result<Self> {
        Ok(Self {
            worker: native::Worker::new(executable)?,
        })
    }

    fn start(
        &self,
        question: Question<'_>,
        limit: usize,
        permit: tokio::sync::OwnedSemaphorePermit,
    ) -> io::Result<native::Request> {
        #[cfg(any(
            all(target_os = "linux", not(target_env = "ohos")),
            target_os = "freebsd"
        ))]
        {
            self.worker.start(question, limit, permit)
        }
        #[cfg(not(any(
            all(target_os = "linux", not(target_env = "ohos")),
            target_os = "freebsd"
        )))]
        {
            native::start(question, limit, permit)
        }
    }
}

/// Early process argument for the original system resolver worker.
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd"
))]
pub const SYSTEM_DNS_WORKER_ARGUMENT: &str = nss::WORKER_ARGUMENT;

/// Perform one blocking name-service operation in the selected worker process.
/// The program passes arguments after [`SYSTEM_DNS_WORKER_ARGUMENT`] and
/// exits when this function returns. The worker checks its original parent.
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd"
))]
pub fn serve_system_dns_worker(
    args: impl Iterator<Item = std::ffi::OsString>,
    input: impl io::Read,
    output: impl io::Write,
) -> io::Result<()> {
    nss::serve_worker(args, input, output)
}

#[derive(Clone, Copy)]
#[cfg_attr(
    not(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "macos",
        windows
    )),
    expect(dead_code, reason = "This target has no native query implementation")
)]
enum Question<'a> {
    A(&'a str),
    Aaaa(&'a str),
    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd"
    ))]
    Any(&'a str),
    Ptr(IpAddr),
}

#[cfg(any(target_os = "macos", windows))]
impl Question<'_> {
    fn name<'a>(&'a self, reverse: &'a mut [u8; 80]) -> io::Result<&'a str> {
        match *self {
            Self::A(hostname) | Self::Aaaa(hostname) => Ok(hostname),
            Self::Ptr(address) => {
                let length = gnunet_resolver_service_core::lookup::reverse_name(address, reverse)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                std::str::from_utf8(&reverse[..length]).map_err(io::Error::other)
            }
        }
    }
}

#[derive(PartialEq, Eq)]
#[cfg_attr(
    not(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "macos",
        windows
    )),
    expect(dead_code, reason = "This target has no native answer source")
)]
enum Answer {
    V4(Ipv4Addr),
    V6(Ipv6Addr),
    Name(String),
}

impl Answer {
    fn as_core(&self) -> SystemAnswer<'_> {
        match self {
            Self::V4(address) => SystemAnswer::V4(*address),
            Self::V6(address) => SystemAnswer::V6(*address),
            Self::Name(name) => SystemAnswer::Name(name.as_bytes()),
        }
    }

    #[cfg(any(
        all(target_os = "linux", not(target_env = "ohos")),
        target_os = "freebsd",
        target_os = "macos",
        windows
    ))]
    fn unscoped_ipv6(octets: [u8; 16]) -> Option<Self> {
        let address = Ipv6Addr::from(octets);
        // RESOLVER can carry only the address, without its interface.
        let scoped =
            address.is_unicast_link_local() || address.is_multicast() && octets[1] & 0x0f != 0x0e;
        (!scoped).then_some(Self::V6(address))
    }
}

// Canceled operations may still have native callback loans. Keep the native
// admission bound across service stop/restart until the native owners retire.
#[cfg(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd"
))]
const MAX_OPERATIONS: usize = nss::MAX_OPERATIONS;
#[cfg(not(any(
    all(target_os = "linux", not(target_env = "ohos")),
    target_os = "freebsd"
)))]
const MAX_OPERATIONS: usize = 128;
static NATIVE_SLOTS: LazyLock<Arc<Semaphore>> =
    LazyLock::new(|| Arc::new(Semaphore::new(MAX_OPERATIONS)));
const ANSWERS_PER_QUESTION: usize = 32;

struct Flight {
    lookup: LookupId,
    deadline: MonoInstant,
    requests: [Option<native::Request>; 2],
    answers: [Vec<Answer>; 2],
    failed: bool,
}

impl Flight {
    fn start(query: SystemQuery<'_>, idna: &impl Idna, provider: &SystemDns) -> io::Result<Self> {
        let mut text = [0; MAX_NAME_LENGTH + 1];
        let questions = match query.question {
            SystemQuestion::Forward { family, hostname } => {
                let hostname = ascii_question(hostname, idna, &mut text)?;
                match family {
                    Family::V4 => [Some(Question::A(hostname)), None],
                    Family::V6 => [Some(Question::Aaaa(hostname)), None],
                    #[cfg(any(
                        all(target_os = "linux", not(target_env = "ohos")),
                        target_os = "freebsd"
                    ))]
                    Family::Any => [Some(Question::Any(hostname)), None],
                    #[cfg(not(any(
                        all(target_os = "linux", not(target_env = "ohos")),
                        target_os = "freebsd"
                    )))]
                    Family::Any => [Some(Question::A(hostname)), Some(Question::Aaaa(hostname))],
                }
            }
            SystemQuestion::Reverse(address) => [Some(Question::Ptr(address)), None],
        };
        let mut permits = Arc::clone(&NATIVE_SLOTS)
            .try_acquire_many_owned(if questions[1].is_some() { 2 } else { 1 })
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        let mut requests = [None, None];
        let mut failed = false;
        for (slot, question) in requests.iter_mut().zip(questions) {
            if let Some(question) = question {
                let permit = permits.split(1).ok_or(io::ErrorKind::WouldBlock)?;
                match provider.start(question, ANSWERS_PER_QUESTION, permit) {
                    Ok(request) => *slot = Some(request),
                    Err(_) => failed = true,
                }
            }
        }
        Ok(Self {
            lookup: query.lookup,
            deadline: query.deadline,
            requests,
            answers: [Vec::new(), Vec::new()],
            failed,
        })
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let mut pending = false;
        for (slot, answers) in self.requests.iter_mut().zip(&mut self.answers) {
            if let Some(request) = slot {
                match request.poll(cx) {
                    Poll::Pending => pending = true,
                    Poll::Ready(result) => {
                        *slot = None;
                        match result {
                            Ok(result) => *answers = result,
                            Err(_) => self.failed = true,
                        }
                    }
                }
            }
        }
        if pending {
            Poll::Pending
        } else {
            Poll::Ready(())
        }
    }
}

fn ascii_question<'a>(name: &str, idna: &impl Idna, output: &'a mut [u8]) -> io::Result<&'a str> {
    let length = idna.to_ascii(name.as_bytes(), output).map_err(|error| {
        let kind = match error {
            Error::Malformed | Error::InvalidInput | Error::TooLarge | Error::Capacity => {
                io::ErrorKind::InvalidInput
            }
            _ => io::ErrorKind::Other,
        };
        io::Error::new(kind, error)
    })?;
    let bytes = output.get(..length).ok_or(io::ErrorKind::InvalidData)?;
    if bytes.is_empty() || !bytes.is_ascii() || bytes.contains(&0) || bytes.contains(&b'\\') {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    std::str::from_utf8(bytes).map_err(io::Error::other)
}

pub(super) struct Queries {
    provider: SystemDns,
    flights: Vec<Option<Flight>>,
    cursor: usize,
    pub(super) completed: Option<Completed>,
}

pub(super) struct Completed(Flight);

impl Completed {
    pub(super) fn lookup(&self) -> LookupId {
        self.0.lookup
    }

    pub(super) fn failed(&self) -> bool {
        self.0.failed
    }

    pub(super) fn answers(&self) -> impl Iterator<Item = SystemAnswer<'_>> {
        self.0.answers.iter().flatten().map(Answer::as_core)
    }
}

impl Queries {
    pub(super) fn new(capacity: usize, provider: SystemDns) -> Result<Self, Error> {
        let mut flights = Vec::new();
        flights
            .try_reserve_exact(capacity)
            .map_err(|_| Error::Capacity)?;
        flights.resize_with(capacity, || None);
        Ok(Self {
            provider,
            flights,
            cursor: 0,
            completed: None,
        })
    }

    pub(super) fn start(&mut self, query: SystemQuery<'_>, idna: &impl Idna) -> io::Result<()> {
        let slot = self
            .flights
            .get_mut(query.lookup.resource_id().index as usize)
            .ok_or_else(|| io::Error::from(io::ErrorKind::WouldBlock))?;
        if slot.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        *slot = Some(Flight::start(query, idna, &self.provider)?);
        Ok(())
    }

    pub(super) fn cancel(&mut self, lookup: LookupId) {
        if let Some(slot) = self.flights.get_mut(lookup.resource_id().index as usize)
            && slot.as_ref().is_some_and(|flight| flight.lookup == lookup)
        {
            *slot = None;
        }
        if self
            .completed
            .as_ref()
            .is_some_and(|result| result.lookup() == lookup)
        {
            self.completed = None;
        }
    }

    pub(super) fn expire(&mut self, now: MonoInstant) {
        for slot in &mut self.flights {
            if slot.as_ref().is_some_and(|flight| flight.deadline <= now) {
                *slot = None;
            }
        }
        if self
            .completed
            .as_ref()
            .is_some_and(|result| result.0.deadline <= now)
        {
            self.completed = None;
        }
    }

    pub(super) fn next_deadline(&self) -> Option<MonoInstant> {
        self.flights
            .iter()
            .flatten()
            .map(|flight| flight.deadline)
            .chain(self.completed.iter().map(|result| result.0.deadline))
            .min()
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>, deliver: bool) -> Poll<()> {
        if deliver && self.completed.is_some() {
            return Poll::Ready(());
        }
        let count = self.flights.len();
        for offset in 0..count {
            let index = (self.cursor + offset) % count;
            let slot = &mut self.flights[index];
            if let Some(flight) = slot
                && flight.poll(cx).is_ready()
                && deliver
            {
                self.cursor = (index + 1) % count;
                self.completed = slot.take().map(Completed);
                return Poll::Ready(());
            }
        }
        Poll::Pending
    }

    pub(super) fn stop(&mut self) {
        self.flights.fill_with(|| None);
        self.completed = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_idna::{Backend, NativeProfile, Workspace};

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Assert that IDNA keeps the system's search qualification"
    )]
    fn normalizes_names_without_changing_search_qualification() -> io::Result<()> {
        let mut workspace = Workspace::new();
        let idna = Backend::new(
            &mut workspace,
            gnunet_idna::Limits::GNUNET,
            NativeProfile::Libunistring1_5Unicode18_0,
        );
        let mut output = [0; MAX_NAME_LENGTH + 1];
        assert_eq!(ascii_question("faß", &idna, &mut output)?, "xn--fa-hia");
        assert_eq!(
            ascii_question("faß.de.", &idna, &mut output)?,
            "xn--fa-hia.de."
        );
        Ok(())
    }
}
