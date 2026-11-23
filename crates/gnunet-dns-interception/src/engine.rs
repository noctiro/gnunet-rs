//! Fixed directories, shared actual-length payload accounting and original
//! effects. No hidden resolver, process, native source or output success exists.
use crate::{Decision, MAX_DNS_BYTES, Query, wire};
use gnunet_types::Error;
mod decisions;
mod output;
mod retirement;
mod storage;
mod types;
use storage::{Directory, Payload, Payloads};
use types::Scope;
pub use types::{
    Client, Destination, Effect, Instance, Limits, OutputPhase, Phase, PreparedReply, Request,
    Resolve, Source, Work,
};
#[derive(Clone, Copy)]
struct App {
    serial: u64,
    flags: u32,
}
#[derive(Clone, Copy)]
struct Output<'id> {
    effect: Effect<'id>,
    phase: OutputPhase,
}
struct Row<'id> {
    serial: u64,
    source: Source<'id>,
    id: [u8; 8],
    payload: Payload,
    phase: Phase,
    eligible: u64,
    water: u64,
    current: Option<Client<'id>>,
    output: Option<Output<'id>>,
    resolver: Option<Resolve<'id>>,
    until: u64,
    expired: bool,
}
/// Interception engine with heap directories and a shared payload budget.
#[cfg(feature = "alloc")]
pub type Engine<'id> = Owner<'id, 'static, 0, 0>;

/// Interception engine with inline directories and caller-owned payload storage.
pub type FixedEngine<'id, 'space, const CLIENTS: usize, const REQUESTS: usize> =
    Owner<'id, 'space, CLIENTS, REQUESTS>;

/// Shared phase machine for fixed and allocating engines.
pub struct Owner<'id, 'space, const CLIENTS: usize, const REQUESTS: usize> {
    scope: Scope<'id>,
    limits: Limits,
    apps: Directory<App, CLIENTS>,
    rows: Directory<Row<'id>, REQUESTS>,
    payloads: Payloads<'space>,
    source: Option<Source<'id>>,
    used: usize,
    last_client: u64,
    closed: bool,
}
#[cfg(feature = "alloc")]
impl<'id> Engine<'id> {
    /// Allocate bounded directories; native ports remain explicitly external.
    pub fn new(instance: &'id Instance, limits: Limits) -> Result<Self, Error> {
        check_limits(limits)?;
        Self::from_storage(
            instance,
            limits,
            Directory::shared(limits.clients)?,
            Directory::shared(limits.requests)?,
            Payloads::Shared,
        )
    }
}

impl<'id, 'space, const C: usize, const R: usize> Owner<'id, 'space, C, R> {
    /// Borrow one fixed payload lane per request without allocating memory.
    ///
    /// The first R times payload_bytes bytes are reserved for this engine and
    /// erased on retirement or drop. Any excess caller storage is untouched.
    ///
    /// # Errors
    /// Refuses unsupported capacities, size overflow, insufficient storage or
    /// allocation-domain serial exhaustion.
    pub fn with_storage(
        instance: &'id Instance,
        payload_bytes: usize,
        arena: &'space mut [u8],
    ) -> Result<Self, Error> {
        let bytes = R.checked_mul(payload_bytes).ok_or(Error::Overflow)?;
        let limits = Limits {
            clients: C,
            requests: R,
            bytes,
            payload_bytes,
        };
        check_limits(limits)?;
        let arena = arena.get_mut(..bytes).ok_or(Error::Capacity)?;
        Self::from_storage(
            instance,
            limits,
            Directory::inline(),
            Directory::inline(),
            Payloads::Fixed {
                bytes: arena,
                lane: payload_bytes,
            },
        )
    }

    fn from_storage(
        instance: &'id Instance,
        limits: Limits,
        apps: Directory<App, C>,
        rows: Directory<Row<'id>, R>,
        payloads: Payloads<'space>,
    ) -> Result<Self, Error> {
        let scope = Scope {
            domain: instance,
            serial: instance.allocate()?,
        };
        Ok(Self {
            scope,
            limits,
            apps,
            rows,
            payloads,
            source: None,
            used: 0,
            last_client: 0,
            closed: false,
        })
    }
    fn live(&self) -> Result<(), Error> {
        if self.closed {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn app(&self, c: Client<'id>) -> Result<App, Error> {
        self.live()?;
        if c.scope != self.scope {
            return Err(Error::StaleGeneration);
        }
        let app = self
            .apps
            .get(c.row)
            .and_then(Option::as_ref)
            .ok_or(Error::StaleGeneration)?;
        if app.serial != c.serial {
            return Err(Error::StaleGeneration);
        }
        Ok(*app)
    }
    fn row(&self, r: Request<'id>) -> Result<&Row<'id>, Error> {
        if r.scope != self.scope {
            return Err(Error::StaleGeneration);
        }
        let row = self
            .rows
            .get(r.row)
            .and_then(Option::as_ref)
            .ok_or(Error::StaleGeneration)?;
        if row.serial != r.serial {
            return Err(Error::StaleGeneration);
        }
        Ok(row)
    }
    fn row_mut(&mut self, r: Request<'id>) -> Result<&mut Row<'id>, Error> {
        self.row(r)?;
        self.rows[r.row].as_mut().ok_or(Error::StaleGeneration)
    }
    fn handle(&self, row: usize) -> Result<Request<'id>, Error> {
        Ok(Request {
            scope: self.scope,
            row,
            serial: self.rows[row]
                .as_ref()
                .ok_or(Error::StaleGeneration)?
                .serial,
        })
    }
    /// Mint only after actual original native source ownership was attached. This
    /// is source identity, not proof that routing/interception setup is finished.
    pub fn attach_source(&mut self) -> Result<Source<'id>, Error> {
        self.live()?;
        if self.source.is_some() {
            return Err(Error::Conflict);
        }
        let source = Source {
            scope: self.scope,
            serial: self.scope.domain.allocate()?,
        };
        self.source = Some(source);
        Ok(source)
    }
    /// Actual accepted MQ allocation; INIT flags initially zero as official.
    pub fn attach_client(&mut self) -> Result<Client<'id>, Error> {
        self.live()?;
        let row = self
            .apps
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let serial = self.scope.domain.allocate()?;
        self.apps[row] = Some(App { serial, flags: 0 });
        self.last_client = serial;
        Ok(Client {
            scope: self.scope,
            row,
            serial,
        })
    }
    /// Actual decoded original INIT, with raw future flag bits preserved.
    pub fn init(&mut self, client: Client<'id>, flags: u32) -> Result<(), Error> {
        self.app(client)?;
        self.apps[client.row]
            .as_mut()
            .ok_or(Error::StaleGeneration)?
            .flags = flags;
        Ok(())
    }
    fn mask(&self, phase: Phase) -> u64 {
        let flag = match phase {
            Phase::RequestMonitor => wire::REQUEST_MONITOR,
            Phase::PreResolution => wire::PRE_RESOLUTION,
            Phase::PostResolution => wire::POST_RESOLUTION,
            Phase::ResponseMonitor => wire::RESPONSE_MONITOR,
            _ => 0,
        };
        self.apps.iter().enumerate().fold(0, |bits, (i, a)| {
            if a.is_some_and(|a| a.flags & flag != 0) {
                bits | (1u64 << i)
            } else {
                bits
            }
        })
    }
    fn enter(&mut self, r: Request<'id>, phase: Phase) -> Result<(), Error> {
        let mask = self.mask(phase);
        let water = self.last_client;
        let row = self.row_mut(r)?;
        row.phase = phase;
        row.eligible = mask;
        row.water = water;
        row.current = None;
        row.output = None;
        Ok(())
    }
    /// Admit a validated DNS query from the original attached source. Duplicate
    /// DNS transaction IDs remain independent requests; native reply authority
    /// and endpoint/scope metadata stay with that source.
    ///
    /// # Errors
    /// Refuses a retired or foreign source, an invalid deadline, payload or
    /// request capacity exhaustion, and allocation-domain serial exhaustion.
    pub fn intercept(
        &mut self,
        source: Source<'id>,
        query: Query<'_>,
        now: u64,
        until: u64,
    ) -> Result<Request<'id>, Error> {
        self.live()?;
        if self.source != Some(source) {
            return Err(Error::StaleGeneration);
        }
        if now >= until || until == u64::MAX {
            return Err(Error::Deadline);
        }
        let payload = query.bytes();
        if payload.len() > self.limits.payload_bytes {
            return Err(Error::TooLarge);
        }
        let row = self
            .rows
            .iter()
            .position(Option::is_none)
            .ok_or(Error::Capacity)?;
        let free = self.free_bytes();
        let serial = self.scope.domain.allocate()?;
        let payload = self.payloads.insert(row, free, payload)?;
        let r = Request {
            scope: self.scope,
            row,
            serial,
        };
        let mask = self.mask(Phase::RequestMonitor);
        self.used += payload.charge();
        self.rows[row] = Some(Row {
            serial,
            source,
            id: serial.to_be_bytes(),
            payload,
            phase: Phase::RequestMonitor,
            eligible: mask,
            water: self.last_client,
            current: None,
            output: None,
            resolver: None,
            until,
            expired: false,
        });
        Ok(r)
    }
    /// Original finite deadline metadata.
    pub fn deadline(&self, r: Request<'id>) -> Result<u64, Error> {
        Ok(self.row(r)?.until)
    }
    /// Exact current original DNS bytes for actual provider submission.
    pub fn payload(&self, r: Request<'id>) -> Result<&[u8], Error> {
        self.payloads.get(r.row, &self.row(r)?.payload)
    }
    /// Pure lookup of the next bounded requirement. Phase transitions use actual
    /// prior results; current phase's client bitmap freezes eligibility at entry.
    pub fn next_work(&mut self, r: Request<'id>) -> Result<Work<'id>, Error> {
        self.next_work_with_post(r, &mut [], |_, _| Ok(None))
    }

    /// Advance with an optional in-process response transformer. After all
    /// eligible POST clients finish, invoke it with the exact current reply
    /// and caller scratch. An optional replacement becomes the original
    /// RESPONSE_MONITOR and source payload. A failure leaves the request in
    /// POST for the caller to abort or retry. Other transitions never call it.
    pub fn next_work_with_post(
        &mut self,
        r: Request<'id>,
        scratch: &mut [u8],
        post: impl FnOnce(&[u8], &mut [u8]) -> Result<Option<usize>, Error>,
    ) -> Result<Work<'id>, Error> {
        let mut post = Some(post);
        for _ in 0..6 {
            let row = self.row(r)?;
            if row.expired || row.phase == Phase::Dropped {
                if let Some(out) = row.output {
                    return Ok(Work::Close(out.effect.destination));
                }
                if let Some(job) = row.resolver {
                    return Ok(Work::Cancel(job));
                }
                return Ok(Work::Retire(r));
            }
            if row.output.is_some() {
                return Err(Error::WouldBlock);
            }
            if row.phase == Phase::Resolver {
                return if row.resolver.is_some() {
                    Err(Error::WouldBlock)
                } else {
                    Ok(Work::Resolve(r))
                };
            }
            if row.phase == Phase::Output {
                return Ok(Work::Source {
                    request: r,
                    source: row.source,
                });
            }
            let eligible = row.eligible;
            let water = row.water;
            let next = self
                .apps
                .iter()
                .enumerate()
                .filter_map(|(i, a)| {
                    let a = a.as_ref()?;
                    (eligible & (1u64 << i) != 0 && a.serial <= water).then_some((i, *a))
                })
                .max_by_key(|(_, a)| a.serial);
            if let Some((index, app)) = next {
                let client = Client {
                    scope: self.scope,
                    row: index,
                    serial: app.serial,
                };
                self.row_mut(r)?.current = Some(client);
                return Ok(Work::Client { request: r, client });
            }
            let phase = match self.row(r)?.phase {
                Phase::RequestMonitor => Phase::PreResolution,
                Phase::PreResolution => Phase::Resolver,
                Phase::PostResolution => {
                    let transform = post.take().ok_or(Error::Conflict)?;
                    if let Some(used) = transform(self.payload(r)?, scratch)? {
                        self.replace(r, scratch.get(..used).ok_or(Error::Capacity)?)?;
                    }
                    Phase::ResponseMonitor
                }
                Phase::ResponseMonitor => Phase::Output,
                _ => return Err(Error::Conflict),
            };
            self.enter(r, phase)?;
        }
        Err(Error::Conflict)
    }

    fn free_bytes(&self) -> usize {
        self.limits.bytes.saturating_sub(self.used)
    }
}

fn check_limits(limits: Limits) -> Result<(), Error> {
    if !(1..=64).contains(&limits.clients)
        || limits.requests == 0
        || !(12..=MAX_DNS_BYTES).contains(&limits.payload_bytes)
        || limits.bytes < limits.payload_bytes
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
