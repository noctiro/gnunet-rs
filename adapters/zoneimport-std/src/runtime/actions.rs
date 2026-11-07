//! Translate one actual pure action to its original native operation exactly once.
use super::*;
use gnunet_crypto::Entropy;
use zeroize::Zeroize;

pub(super) struct Random {
    failure: Option<getrandom::Error>,
}
impl Random {
    fn new() -> Self {
        Self { failure: None }
    }
}
impl Entropy for Random {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Fault> {
        match getrandom::fill(output) {
            Ok(()) => Ok(()),
            Err(error) => {
                output.zeroize();
                self.failure = Some(error);
                Err(Fault::Entropy)
            }
        }
    }
}
enum Owned {
    Create {
        zone: ZoneId,
        name: String,
    },
    Check {
        parent: ZoneId,
        label: String,
    },
    Delegate {
        parent: ZoneId,
        label: String,
        records: Records,
    },
    Scan {
        zone: ZoneId,
    },
    Query {
        hostname: String,
    },
    Store {
        answer: AnswerId,
        zone: ZoneId,
        label: String,
    },
    Retire {
        kind: Kind,
        admitted: bool,
    },
}
fn text(value: &str) -> Result<String, Error> {
    let mut output = String::new();
    output
        .try_reserve_exact(value.len())
        .map_err(|_| Fault::Capacity)?;
    output.push_str(value);
    Ok(output)
}
impl<'id> Runtime<'id> {
    fn ns_ready(&mut self) -> Result<(), Error> {
        if self.namestore.is_none() {
            self.namestore = Some(namestore::Client::new(
                self.instances.namestore,
                self.ports.namestore.duplicate()?,
                self.limits.namestore,
            )?);
        }
        Ok(())
    }
    fn ns_room(&self, bytes: usize) -> bool {
        let Some(client) = &self.namestore else {
            return true;
        };
        if client.pending() >= self.limits.namestore.operations {
            return false;
        }
        let queued = self
            .pending
            .iter()
            .flatten()
            .filter(|row| {
                !row.written
                    && matches!(
                        row.native,
                        Native::Check { .. } | Native::Delegate { .. } | Native::Store { .. }
                    )
            })
            .fold(0usize, |sum, row| sum.saturating_add(row.wire_bytes));
        queued
            .checked_add(bytes)
            .is_some_and(|sum| sum <= self.limits.namestore.source_bytes)
    }
    fn deferred(
        &mut self,
        index: usize,
        job: JobId,
        kind: Kind,
        bounds: Bounds,
        budget: Budget,
    ) -> Result<(), Error> {
        self.core.defer(&job)?;
        self.pending[index] = Some(Pending {
            job,
            kind,
            bounds,
            budget,
            epoch: None,
            wire_bytes: 0,
            written: false,
            retiring: false,
            expired: false,
            started: std::time::Instant::now(),
            exposure: crate::Exposure::Unsent,
            native: Native::Deferred,
        });
        Ok(())
    }
    pub(super) fn requested(&mut self, observe: &mut impl FnMut(Event<'_>)) -> Result<bool, Error> {
        let now = self.clock.sample()?;
        self.last = now;
        let Some(action) = self.core.next_action(now)? else {
            return Ok(false);
        };
        let job = action.job;
        let bounds = action.bounds;
        let (kind, owned) = match action.kind {
            core::ActionKind::CreateZone { zone, name } => (
                Kind::CreateZone,
                Owned::Create {
                    zone,
                    name: text(name)?,
                },
            ),
            core::ActionKind::CheckDelegation { parent, label, .. } => (
                Kind::CheckDelegation,
                Owned::Check {
                    parent,
                    label: text(label)?,
                },
            ),
            core::ActionKind::Delegate {
                parent,
                label,
                record,
                ..
            } => (
                Kind::Delegate,
                Owned::Delegate {
                    parent,
                    label: text(label)?,
                    records: Records::one(record)?,
                },
            ),
            core::ActionKind::ScanCache { zone } => (Kind::ScanCache, Owned::Scan { zone }),
            core::ActionKind::Query { hostname, .. } => (
                Kind::Query,
                Owned::Query {
                    hostname: text(hostname)?,
                },
            ),
            core::ActionKind::Store {
                answer,
                zone,
                label,
                ..
            } => (
                Kind::Store,
                Owned::Store {
                    answer,
                    zone,
                    label: text(label)?,
                },
            ),
            core::ActionKind::Retire { kind, admitted } => (kind, Owned::Retire { kind, admitted }),
        };
        if let Owned::Retire { kind, admitted } = owned {
            self.retire_action(job, kind, admitted, observe)?;
            return Ok(true);
        }
        self.metrics.idle(false);
        let index = self.free()?;
        let budget = match Budget::from_bounds(&self.clock, bounds) {
            Ok(original) => original,
            Err(Fault::Deadline) => {
                let completed = self.core.reject(&job)?;
                self.release(completed)?;
                observe(Event::Deadline {
                    job: job.diagnostic(),
                    kind,
                });
                return Ok(true);
            }
            Err(cause) => return Err(cause.into()),
        };
        let mut wire_bytes = 0;
        let native = match owned {
            Owned::Create { zone, name } => {
                if self.ambiguous.iter().any(|candidate| candidate == &name) {
                    let result = self.core.reject(&job)?;
                    self.release(result)?;
                    return Err(Fault::Conflict.into());
                }
                let client = self.identity.as_ref().ok_or(Fault::NotReady)?;
                if client.pending() >= self.limits.identity.operations {
                    self.deferred(index, job, kind, bounds, budget)?;
                    return Ok(true);
                }
                let name = self.names.domain(&name, self.limits.identity.name_bytes)?;
                let mut random = Random::new();
                let secret =
                    match identity::SecretKey::generate(identity::KeyType::Eddsa, &mut random) {
                        Ok(secret) => secret,
                        Err(error) => {
                            return Err(match random.failure {
                                Some(error) => {
                                    Error::Dns(gnunet_dnsstub_host::HostError::Entropy(error))
                                }
                                None => error.into(),
                            });
                        }
                    };
                budget.check(&self.clock)?;
                let operation = self
                    .identity
                    .as_mut()
                    .ok_or(Fault::NotReady)?
                    .create(&name, secret, budget.until)
                    .map_err(Error::Identity)?;
                Native::Create { operation, zone }
            }
            Owned::Check { parent, label } => {
                self.ns_ready()?;
                let label = self.names.label(&label)?;
                let key = self.key(&parent)?.try_clone_secret();
                let length = namestore::ipc::Request::Lookup {
                    rid: 0,
                    zone: key.view()?,
                    label: namestore::ipc::CString::new(&label)?,
                    filter: 1,
                    unused: 0,
                }
                .encoded_len()?;
                if !self.ns_room(length) {
                    self.deferred(index, job, kind, bounds, budget)?;
                    return Ok(true);
                }
                budget.check(&self.clock)?;
                let operation = self.namestore.as_mut().ok_or(Fault::NotReady)?.lookup(
                    &key,
                    &label,
                    1,
                    budget.until,
                )?;
                wire_bytes = length;
                Native::Check { operation, label }
            }
            Owned::Delegate {
                parent,
                label,
                records,
            } => {
                self.ns_ready()?;
                let label = self.names.label(&label)?;
                let sets = records.set(&label, self.limits.namestore)?;
                let key = self.key(&parent)?.try_clone_secret();
                let length = namestore::ipc::STORE_PREFIX
                    .checked_add(identity::ipc::KEY_LEN)
                    .and_then(|n| n.checked_add(sets.len()))
                    .ok_or(Fault::Overflow)?;
                if !self.ns_room(length) {
                    self.deferred(index, job, kind, bounds, budget)?;
                    return Ok(true);
                }
                budget.check(&self.clock)?;
                let operation = self.namestore.as_mut().ok_or(Fault::NotReady)?.store(
                    &key,
                    namestore::ipc::RecordSets::new(&sets, 1)?,
                    true,
                    budget.until,
                )?;
                wire_bytes = length;
                Native::Delegate { operation }
            }
            Owned::Scan { zone } => {
                let key = self.key(&zone)?.try_clone_secret();
                let source = self.ports.namestore.duplicate()?;
                budget.check(&self.clock)?;
                let iterator = namestore::ZoneIterator::new(
                    self.instances.namestore,
                    source,
                    Some(&key),
                    1,
                    budget.until,
                    self.limits.namestore,
                )?;
                self.metrics.add(15, 1);
                Native::Scan(Box::new(Scan {
                    iterator,
                    next_pending: false,
                    closed: false,
                }))
            }
            Owned::Query { hostname } => {
                if self.dns.pending_requests() >= self.limits.dns_requests {
                    self.deferred(index, job, kind, bounds, budget)?;
                    return Ok(true);
                }
                let mut id = [0; 2];
                getrandom::fill(&mut id)
                    .map_err(|error| Error::Dns(gnunet_dnsstub_host::HostError::Entropy(error)))?;
                let bytes = response::query(&hostname, id)?;
                budget.check(&self.clock)?;
                let actual = self.dns.resolve(&bytes).map_err(Error::Dns)?;
                // Keep the newly admitted source mapping before consuming any
                // original eviction notification from this real bounded owner.
                let query = Query {
                    request: Some(actual.request),
                    bytes,
                    hostname,
                    tcp_server: None,
                    tcp: None,
                };
                self.pending[index] = Some(Pending {
                    job: job.clone(),
                    kind,
                    bounds,
                    budget,
                    epoch: None,
                    wire_bytes: 0,
                    written: false,
                    retiring: false,
                    expired: false,
                    started: std::time::Instant::now(),
                    exposure: crate::Exposure::Unsent,
                    native: Native::Query(Box::new(query)),
                });
                self.core.admitted(&job)?;
                observe(Event::Admitted {
                    job: job.diagnostic(),
                    kind,
                });
                if let Some(evicted) = actual.evicted {
                    self.evicted(evicted, observe)?;
                }
                return Ok(true);
            }
            Owned::Store {
                answer,
                zone,
                label,
            } => {
                self.ns_ready()?;
                let records = &self
                    .answers
                    .iter()
                    .flatten()
                    .find(|row| row.id == answer)
                    .ok_or(Fault::StaleGeneration)?
                    .records;
                let label = self.names.label(&label)?;
                let sets = records.set(&label, self.limits.namestore)?;
                let key = self.key(&zone)?.try_clone_secret();
                let length = namestore::ipc::STORE_PREFIX
                    .checked_add(identity::ipc::KEY_LEN)
                    .and_then(|n| n.checked_add(sets.len()))
                    .ok_or(Fault::Overflow)?;
                if !self.ns_room(length) {
                    self.deferred(index, job, kind, bounds, budget)?;
                    return Ok(true);
                }
                budget.check(&self.clock)?;
                let operation = self.namestore.as_mut().ok_or(Fault::NotReady)?.store(
                    &key,
                    namestore::ipc::RecordSets::new(&sets, 1)?,
                    true,
                    budget.until,
                )?;
                wire_bytes = length;
                Native::Store { operation, answer }
            }
            Owned::Retire { .. } => return Err(Fault::Conflict.into()),
        };
        self.pending[index] = Some(Pending {
            job: job.clone(),
            kind,
            bounds,
            budget,
            epoch: None,
            wire_bytes,
            written: false,
            retiring: false,
            expired: false,
            started: std::time::Instant::now(),
            exposure: crate::Exposure::Unsent,
            native,
        });
        // This actual row precedes the original admission fact; a later error
        // leaves its native token owned for actual finally, never a fake retry.
        self.core.admitted(&job)?;
        observe(Event::Admitted {
            job: job.diagnostic(),
            kind,
        });
        Ok(true)
    }
}
