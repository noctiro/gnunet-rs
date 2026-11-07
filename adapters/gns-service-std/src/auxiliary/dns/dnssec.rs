//! Original-budget DNSSEC owner for authenticated GNS2DNS DS delegations.
//! Native exchanges remain in the parent's original Run; AD grants no trust.
mod crypto;
mod roots;

use super::{
    Budget, Decision, DnsReport, Error, Inner, OperationFuture, OwnedQuery, OwnedRecord, Query,
    QueryFlags, RecursiveDns, Reply, Run, Secure, SecuredRequest, Shared, address, address_data,
    canonical, cooperate, copy_slice, kind, push_server, suffix, terminal, valid_server, wire_name,
    zeroes,
};
use crate::{
    Bounds, Operation, Value,
    native::{Error as NativeError, Report},
};
use gnunet_dns::{
    Name,
    dnssec::{self as core, Rrset, Scratch, TrustedKeys, Validated, denial},
};
use gnunet_gns::{Origin, Record, RecordFlags, RecordType};
use gnunet_service_runtime::clock::RuntimeClock;
use gnunet_types::Error as Fault;
use std::{
    cell::{Cell, RefCell},
    future::Future,
    marker::PhantomData,
    net::SocketAddr,
    pin::Pin,
    rc::Rc,
    sync::Arc,
};

/// Explicit native validation resources; every operation also keeps the original
/// parent DNS exchange/depth/packet limits and the original absolute Bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum actual signature/digest/SHA-1 calls across this original query.
    pub crypto_operations: usize,
    /// Original consumable denial scanning/copying budget.
    pub denial_steps: usize,
    /// Original consumable NSEC3 SHA-1-call budget.
    pub denial_hashes: usize,
    /// Extra NSEC3 iterations allowed by local policy; zero follows RFC 9276.
    pub nsec3_iterations: u16,
    /// Maximum actual-size canonical signature workspace.
    pub scratch_bytes: usize,
    /// Maximum actual signed zone cuts crossed in one chain.
    pub zones: usize,
    /// Operator/vendor root DS records, used only after a real anchor change.
    pub root_ds: &'static [&'static [u8]],
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            crypto_operations: 4096,
            denial_steps: 16 * 1024 * 1024,
            denial_hashes: 2048,
            nsec3_iterations: 0,
            scratch_bytes: 8 * 1024 * 1024,
            zones: 32,
            root_ds: roots::CURRENT,
        }
    }
}
impl RecursiveDns {
    /// Install actual DNSKEY/RRSIG/denial verification on this same DNS factory.
    /// No socket, thread, task, broker or key is created by this constructor.
    pub fn with_dnssec(mut self, limits: Limits) -> Result<Self, Error> {
        if self.shared.limits.bytes < 512
            || limits.crypto_operations == 0
            || limits.denial_steps == 0
            || limits.denial_hashes == 0
            || limits.scratch_bytes == 0
            || limits.scratch_bytes > 8 * 1024 * 1024
            || limits.zones == 0
            || limits.root_ds.len() > 64
        {
            return Err(Fault::InvalidInput.into());
        }
        for ds in limits.root_ds {
            check_ds(ds)?;
        }
        self.security = Some(Arc::new(Validator {
            shared: self.shared.clone(),
            limits,
        }));
        Ok(self)
    }
}
struct Validator {
    shared: Arc<Shared>,
    limits: Limits,
}
impl Secure for Validator {
    fn clock(&self) -> Arc<dyn RuntimeClock> {
        self.shared.clock.clone()
    }
    fn query<'id>(
        &self,
        request: SecuredRequest,
        bounds: Bounds,
    ) -> Result<
        Box<dyn Operation<Error = NativeError<'id>, Report = Report<'id>> + 'id>,
        NativeError<'id>,
    > {
        super::super::guard(bounds)?;
        let trace = Rc::new(RefCell::new(DnsReport::new(bounds)));
        let run = Run {
            shared: self.shared.clone(),
            bounds,
            trace: trace.clone(),
        };
        let budget = run
            .budget(request.remaining_steps)
            .map_err(NativeError::Dns)?;
        let mut task = Task {
            run,
            limits: self.limits,
            budget,
            crypto_left: Cell::new(self.limits.crypto_operations),
            denial_work: denial::Work::new(self.limits.denial_steps, self.limits.denial_hashes),
        };
        let future: OperationFuture = Box::pin(async move {
            let records = task.resolve(request).await?;
            Ok(Value::Records {
                records,
                spent: task.budget.spent(),
            })
        });
        super::super::guard(bounds)?;
        // The original parent Query::Inner::Secured owns the one actual permit.
        // This nested owner uses the same retirement/trace implementation only.
        Ok(Box::new(Query {
            inner: Inner::Owned(OwnedQuery {
                future: Some(future),
                permit: None,
                bounds,
                alarm: None,
                trace: Some(trace),
                closing: false,
                lifetime: PhantomData,
            }),
        }))
    }
}

struct DsData {
    records: Vec<Vec<u8>>,
    expires: u64,
}
struct Route {
    zone: Vec<u8>,
    servers: Vec<SocketAddr>,
    recursive: bool,
}
struct Anchor {
    zone: Vec<u8>,
    ds: Arc<DsData>,
    route: Route,
}
struct Keys {
    zone: Vec<u8>,
    ds: Arc<DsData>,
    records: Vec<OwnedRecord>,
}
enum Chain {
    Secure(Keys),
    Insecure { expires: u64 },
}
struct Fetched {
    reply: Reply,
    server: SocketAddr,
}
enum DsResult {
    Cut(Arc<DsData>),
    NotCut,
    NameAbsent,
    Insecure(u64),
    Alias,
}
struct Task {
    run: Run,
    limits: Limits,
    budget: Budget,
    crypto_left: Cell<usize>,
    denial_work: denial::Work,
}
type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<Fetched, Error>> + 'a>>;

impl Task {
    async fn resolve(&mut self, request: SecuredRequest) -> Result<Vec<Record>, Error> {
        let mut name = wire_name(&request.name)?;
        let authority = wire_name(&request.authority)?;
        if !suffix(&name, &authority) || request.security.is_empty() {
            return Err(Fault::InvalidInput.into());
        }
        let wanted = kind(request.record_type)?;
        // RFC 4035 section 2.2: RRSIGs do not form RRsets and must not be
        // signed themselves. RFC 8482 section 7 leaves standalone QTYPE=RRSIG
        // behavior unspecified. This required-security API rejects that query
        // explicitly; it never authenticates metadata through a packet AD bit
        // or fabricates an RRSIG-over-RRSIG chain.
        if matches!(wanted, 0 | 41 | 46 | 249..=254) {
            return Err(Fault::Unsupported.into());
        }
        let now = self.run.now(self.run.bounds.until())?.as_micros();
        let server = SocketAddr::new(request.server, self.run.shared.limits.port);
        valid_server(server)?;
        let mut ds = Vec::new();
        ds.try_reserve_exact(request.security.len())
            .map_err(Error::allocation)?;
        let mut expires = u64::MAX;
        for record in request.security {
            self.run.native(self.run.bounds.hard())?;
            if record.record_type.value() != 43 {
                return Err(Fault::Unsupported.into());
            }
            check_ds(&record.data)?;
            let end = if record.flags.contains(RecordFlags::RELATIVE_EXPIRATION) {
                now.saturating_add(record.expiration_time)
            } else {
                record.expiration_time
            };
            if end <= now {
                continue;
            }
            expires = expires.min(end);
            ds.push(record.data);
        }
        if ds.is_empty() {
            return Err(Fault::Deadline.into());
        }
        let anchor = Anchor {
            route: Route {
                zone: copy_slice(&authority)?,
                servers: vec![server],
                recursive: false,
            },
            zone: authority,
            ds: Arc::new(DsData {
                records: ds,
                expires,
            }),
        };
        // Even if a later CNAME leaves this namespace, the supplied DS anchor
        // must really authenticate its DNSKEY RRset before any result is used.
        let mut original_keys = Some(
            self.load_keys(&anchor.zone, anchor.ds.clone(), &anchor.route)
                .await?,
        );
        let mut seen = Vec::new();
        let mut alias_cap = u64::MAX;
        let mut all_secure = true;
        loop {
            self.run.now(self.run.bounds.until())?;
            if seen.contains(&name) || seen.len() >= self.run.shared.limits.depth {
                return Err(Fault::Capacity.into());
            }
            seen.try_reserve(1).map_err(Error::allocation)?;
            seen.push(copy_slice(&name)?);
            let parent_query = wanted == 43 && name != [0];
            let chain_name = if parent_query {
                parent_wire(&name)?
            } else {
                &name
            };
            let original = suffix(chain_name, &anchor.zone);
            let root;
            let selected = if original {
                &anchor
            } else {
                root = self.root_anchor()?;
                &root
            };
            let keys = if original {
                match original_keys.take() {
                    Some(keys) => keys,
                    None => {
                        self.load_keys(&selected.zone, selected.ds.clone(), &selected.route)
                            .await?
                    }
                }
            } else {
                self.load_keys(&selected.zone, selected.ds.clone(), &selected.route)
                    .await?
            };
            let chain = self.chain_to(chain_name, keys, &selected.route).await?;
            let fetched = self
                .fetch(copy_slice(&name)?, wanted, &selected.route, 0)
                .await?;
            let code = fetched.reply.code;
            let (decision, secure, cap) = match chain {
                Chain::Secure(keys) => {
                    let (decision, cap) =
                        self.secure_decision(&keys, &fetched.reply, &name, wanted)?;
                    (decision, true, cap)
                }
                Chain::Insecure { expires } => {
                    self.run.trace.borrow_mut().dnssec_insecure = true;
                    let decision =
                        self.run
                            .decision(fetched.reply, &name, wanted, &selected.zone)?;
                    (decision, false, expires)
                }
            };
            all_secure &= secure;
            alias_cap = alias_cap.min(cap);
            match decision {
                Decision::Answer(records) => {
                    let result = self.convert(records, fetched.server, alias_cap)?;
                    self.run.trace.borrow_mut().dnssec_verified = all_secure;
                    return Ok(result);
                }
                Decision::Negative => {
                    self.run.trace.borrow_mut().dnssec_verified = all_secure;
                    return Ok(Vec::new());
                }
                Decision::Alias(target, expiration) if code == 0 => {
                    alias_cap = alias_cap.min(expiration);
                    name = target;
                }
                Decision::Referral { .. } | Decision::Lame | Decision::Alias(..) => {
                    return Err(Fault::Authentication.into());
                }
            }
        }
    }

    fn root_anchor(&self) -> Result<Anchor, Error> {
        if self.limits.root_ds.is_empty() {
            return Err(Fault::NotReady.into());
        }
        if self.run.shared.bootstrap.is_empty() {
            return Err(self.run.shared.unavailable_bootstrap());
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(self.limits.root_ds.len())
            .map_err(Error::allocation)?;
        for raw in self.limits.root_ds {
            records.push(copy_slice(raw)?);
        }
        Ok(Anchor {
            zone: vec![0],
            ds: Arc::new(DsData {
                records,
                expires: u64::MAX,
            }),
            route: Route {
                zone: vec![0],
                servers: copy_slice(&self.run.shared.bootstrap)?,
                recursive: self.run.shared.limits.bootstrap_recursion_desired,
            },
        })
    }

    async fn load_keys(
        &mut self,
        zone: &[u8],
        ds: Arc<DsData>,
        route: &Route,
    ) -> Result<Keys, Error> {
        let fetched = self.fetch(copy_slice(zone)?, 48, route, 0).await?;
        if fetched.reply.code != 0 {
            return Err(Error::response_code(fetched.reply.code));
        }
        let mut records = Vec::new();
        records
            .try_reserve_exact(fetched.reply.answers.len())
            .map_err(Error::allocation)?;
        for record in fetched.reply.answers {
            if record.name == zone && record.class == 1 && matches!(record.kind, 46 | 48) {
                records.push(record);
            }
        }
        let material = Keys {
            zone: copy_slice(zone)?,
            ds,
            records,
        };
        let run = self.run.clone();
        context(
            &run,
            &material,
            None,
            self.limits,
            &self.crypto_left,
            &mut self.denial_work,
            |_, _, _, _, _, _| Ok(()),
        )?;
        Ok(material)
    }

    async fn chain_to(
        &mut self,
        target: &[u8],
        mut keys: Keys,
        route: &Route,
    ) -> Result<Chain, Error> {
        if !suffix(target, &keys.zone) {
            return Err(Fault::Authentication.into());
        }
        let count = Name::from_wire(target)?.labels().count();
        let first = Name::from_wire(&keys.zone)?.labels().count();
        let mut zones = 1;
        for labels in first + 1..=count {
            self.run.now(self.run.bounds.until())?;
            let candidate = keep_wire_labels(target, labels)?;
            let fetched = self.fetch(copy_slice(candidate)?, 43, route, 0).await?;
            match self.ds_result(&keys, &fetched.reply, candidate)? {
                DsResult::Cut(ds) => {
                    zones += 1;
                    if zones > self.limits.zones {
                        return Err(Fault::Capacity.into());
                    }
                    keys = self.load_keys(candidate, ds, route).await?;
                }
                DsResult::Insecure(expires) => return Ok(Chain::Insecure { expires }),
                DsResult::NameAbsent | DsResult::Alias => break,
                DsResult::NotCut => {}
            }
        }
        Ok(Chain::Secure(keys))
    }

    fn ds_result(&mut self, keys: &Keys, reply: &Reply, name: &[u8]) -> Result<DsResult, Error> {
        let run = self.run.clone();
        let limits = self.limits;
        context(
            &run,
            keys,
            Some(reply),
            limits,
            &self.crypto_left,
            &mut self.denial_work,
            |trusted, groups, workspace, backend, work, now| {
                if !matches!(reply.code, 0 | 3) {
                    return Err(Error::response_code(reply.code));
                }
                if let Some(group) = find(groups, name, 43) {
                    if reply.code != 0 {
                        return Err(Fault::Authentication.into());
                    }
                    let validated = verify(trusted, group, groups, now, backend, workspace)?;
                    if validated.wildcard() {
                        return Err(Fault::Authentication.into());
                    }
                    let mut records = Vec::new();
                    records
                        .try_reserve_exact(group.records.len())
                        .map_err(Error::allocation)?;
                    for raw in &group.records {
                        check_ds(raw)?;
                        records.push(copy_slice(raw)?);
                    }
                    return Ok(DsResult::Cut(Arc::new(DsData {
                        records,
                        expires: expires(now, validated.ttl()),
                    })));
                }
                // An authenticated CNAME/DNAME cannot simultaneously be a DS
                // delegation. Do not chase that alias as a new trust anchor.
                let alias = groups
                    .iter()
                    .filter(|group| {
                        group.kind == 39 && group.owner != name && suffix(name, group.owner)
                    })
                    .max_by_key(|group| group.owner.len())
                    .or_else(|| find(groups, name, 5));
                if let Some(group) = alias {
                    let checked = verify(trusted, group, groups, now, backend, workspace)?;
                    wildcard_check(
                        checked, groups, trusted, now, backend, workspace, work, limits,
                    )?;
                    return Ok(if group.kind == 5 {
                        DsResult::NotCut
                    } else {
                        DsResult::Alias
                    });
                }
                let proofs = denial_sets(groups, trusted, now, backend, workspace)?;
                let evidence = denial::Evidence::new(
                    Name::from_wire(&keys.zone)?,
                    1,
                    &proofs,
                    denial_limits(limits, groups.len()),
                    work,
                )?;
                let question = denial::Question {
                    name: Name::from_wire(name)?,
                    kind: 43,
                    class: 1,
                };
                if reply.code == 3 {
                    let proof = denial::prove_nxdomain(question, &evidence, backend, work)?;
                    if proof.security() == denial::Security::InsecureOptOut {
                        return Ok(DsResult::Insecure(expires(now, proof.ttl())));
                    }
                    return Ok(DsResult::NameAbsent);
                }
                let proof = denial::prove_nodata(question, &evidence, backend, work)?;
                if proof.delegation() {
                    return Ok(DsResult::Insecure(expires(now, proof.ttl())));
                }
                Ok(DsResult::NotCut)
            },
        )
    }

    fn secure_decision(
        &mut self,
        keys: &Keys,
        reply: &Reply,
        name: &[u8],
        wanted: u16,
    ) -> Result<(Decision, u64), Error> {
        let run = self.run.clone();
        let limits = self.limits;
        context(
            &run,
            keys,
            Some(reply),
            limits,
            &self.crypto_left,
            &mut self.denial_work,
            |trusted, groups, workspace, backend, work, now| {
                if !matches!(reply.code, 0 | 3) {
                    return Err(Error::response_code(reply.code));
                }
                // A DNAME-generated CNAME has no independent RRSIG (RFC 4035
                // 4.8). Authenticate the DNAME first and bind the exact suffix
                // substitution; never require or fabricate a CNAME signature.
                if let Some(dname) = reply
                    .answers
                    .iter()
                    .filter(|record| {
                        record.class == 1
                            && record.kind == 39
                            && record.name != name
                            && suffix(name, &record.name)
                    })
                    .max_by_key(|record| record.name.len())
                {
                    if reply.code != 0 {
                        return Err(Fault::Authentication.into());
                    }
                    let group = find(groups, &dname.name, 39).ok_or(Fault::Malformed)?;
                    let checked = verify(trusted, group, groups, now, backend, workspace)?;
                    let ttl = wildcard_check(
                        checked, groups, trusted, now, backend, workspace, work, limits,
                    )?;
                    let destination = dname.target.as_ref().ok_or(Fault::Malformed)?;
                    if reply
                        .answers
                        .iter()
                        .filter(|record| {
                            record.class == 1 && record.kind == 39 && record.name == dname.name
                        })
                        .any(|record| record.target.as_ref() != Some(destination))
                    {
                        return Err(Fault::Malformed.into());
                    }
                    let split = name
                        .len()
                        .checked_sub(dname.name.len())
                        .ok_or(Fault::Malformed)?;
                    let mut target = copy_slice(&name[..split])?;
                    target
                        .try_reserve_exact(destination.len())
                        .map_err(Error::allocation)?;
                    target.extend_from_slice(destination);
                    let target = canonical(&target)?;
                    if reply
                        .answers
                        .iter()
                        .filter(|record| {
                            record.class == 1 && record.kind == 5 && record.name == name
                        })
                        .any(|record| record.target.as_ref() != Some(&target))
                    {
                        return Err(Fault::Authentication.into());
                    }
                    let cap = expires(now, ttl).min(dname.expiration);
                    if matches!(wanted, 5 | 255) {
                        let record = OwnedRecord {
                            signed: None,
                            ttl,
                            name: copy_slice(name)?,
                            kind: 5,
                            class: 1,
                            expiration: cap,
                            data: copy_slice(&target)?,
                            target: Some(target),
                        };
                        return Ok((Decision::Answer(vec![record]), cap));
                    }
                    return Ok((Decision::Alias(target, cap), cap));
                }
                let selected = reply
                    .answers
                    .iter()
                    .filter(|record| {
                        record.class == 1
                            && record.name == name
                            && (record.kind == wanted
                                || (wanted == 255 && !matches!(record.kind, 41 | 46)))
                    })
                    .count();
                if selected != 0 {
                    if reply.code != 0 {
                        return Err(Fault::Authentication.into());
                    }
                    let mut records = Vec::new();
                    records
                        .try_reserve_exact(selected)
                        .map_err(Error::allocation)?;
                    let mut cap = u64::MAX;
                    for group in groups.iter().filter(|group| {
                        group.owner == name
                            && (group.kind == wanted
                                || (wanted == 255 && !matches!(group.kind, 41 | 46)))
                            && reply.answers.iter().any(|record| {
                                record.class == 1
                                    && record.name == name
                                    && record.kind == group.kind
                            })
                    }) {
                        let checked = verify(trusted, group, groups, now, backend, workspace)?;
                        let ttl = wildcard_check(
                            checked, groups, trusted, now, backend, workspace, work, limits,
                        )?;
                        cap = cap.min(expires(now, ttl));
                        for record in reply.answers.iter().filter(|record| {
                            record.class == 1 && record.name == name && record.kind == group.kind
                        }) {
                            records.push(copy_record(record)?);
                        }
                    }
                    return Ok((Decision::Answer(records), cap));
                }
                let alias = reply
                    .answers
                    .iter()
                    .find(|record| record.class == 1 && record.name == name && record.kind == 5)
                    .or_else(|| {
                        reply
                            .answers
                            .iter()
                            .filter(|record| {
                                record.class == 1
                                    && record.kind == 39
                                    && record.name != name
                                    && suffix(name, &record.name)
                            })
                            .max_by_key(|record| record.name.len())
                    });
                if let Some(alias) = alias {
                    if reply.code != 0 {
                        return Err(Fault::Authentication.into());
                    }
                    let group = find(groups, &alias.name, alias.kind).ok_or(Fault::Malformed)?;
                    let checked = verify(trusted, group, groups, now, backend, workspace)?;
                    let ttl = wildcard_check(
                        checked, groups, trusted, now, backend, workspace, work, limits,
                    )?;
                    let target = alias.target.as_ref().ok_or(Fault::Malformed)?;
                    if reply
                        .answers
                        .iter()
                        .filter(|record| {
                            record.class == 1
                                && record.name == alias.name
                                && record.kind == alias.kind
                        })
                        .any(|record| record.target.as_ref() != Some(target))
                    {
                        return Err(Fault::Malformed.into());
                    }
                    let target = if alias.kind == 39 {
                        let split = name
                            .len()
                            .checked_sub(alias.name.len())
                            .ok_or(Fault::Malformed)?;
                        let mut value = copy_slice(&name[..split])?;
                        value
                            .try_reserve_exact(target.len())
                            .map_err(Error::allocation)?;
                        value.extend_from_slice(target);
                        canonical(&value)?
                    } else {
                        copy_slice(target)?
                    };
                    let cap = expires(now, ttl).min(alias.expiration);
                    return Ok((Decision::Alias(target, cap), cap));
                }
                // A final negative needs both a genuine parent-trusted SOA and
                // the complete denial proof. Neither an empty packet nor AD is
                // a security receipt. The SOA's signed RDATA minimum caps cache.
                let soa = find(groups, &keys.zone, 6).ok_or(Fault::Authentication)?;
                let checked_soa = verify(trusted, soa, groups, now, backend, workspace)?;
                if checked_soa.wildcard() {
                    return Err(Fault::Authentication.into());
                }
                let mut ttl = checked_soa.ttl();
                for data in &soa.records {
                    let minimum = data
                        .get(data.len().checked_sub(4).ok_or(Fault::Malformed)?..)
                        .ok_or(Fault::Malformed)?;
                    ttl = ttl.min(u32::from_be_bytes(
                        minimum.try_into().map_err(|_| Fault::Malformed)?,
                    ));
                }
                let proofs = denial_sets(groups, trusted, now, backend, workspace)?;
                let evidence = denial::Evidence::new(
                    Name::from_wire(&keys.zone)?,
                    1,
                    &proofs,
                    denial_limits(limits, groups.len()),
                    work,
                )?;
                let question = denial::Question {
                    name: Name::from_wire(name)?,
                    kind: wanted,
                    class: 1,
                };
                let proof = if reply.code == 3 {
                    denial::prove_nxdomain(question, &evidence, backend, work)?
                } else {
                    denial::prove_nodata(question, &evidence, backend, work)?
                };
                if proof.security() != denial::Security::Secure {
                    // The chain walk, not a bare flag on an unrelated negative,
                    // decides whether a real unsigned child may be queried.
                    return Err(Fault::Authentication.into());
                }
                Ok((Decision::Negative, expires(now, ttl.min(proof.ttl()))))
            },
        )
    }

    fn convert(
        &self,
        records: Vec<OwnedRecord>,
        server: SocketAddr,
        cap: u64,
    ) -> Result<Vec<Record>, Error> {
        let now = self.run.now(self.run.bounds.until())?.as_micros();
        let mut out = Vec::new();
        out.try_reserve_exact(records.len())
            .map_err(Error::allocation)?;
        let mut bytes = 0usize;
        for record in records {
            self.run.native(self.run.bounds.hard())?;
            bytes = bytes
                .checked_add(record.data.len())
                .ok_or(Fault::Overflow)?;
            if out.len() == self.run.shared.limits.records || bytes > self.run.shared.limits.bytes {
                return Err(Fault::Capacity.into());
            }
            let end = record.expiration.min(cap);
            let result = Record {
                origin: Origin::Dns(server.ip()),
                expiration_time: if end <= now { 0 } else { end },
                record_type: RecordType::new(u32::from(record.kind)),
                flags: if end <= now {
                    RecordFlags::RELATIVE_EXPIRATION
                } else {
                    RecordFlags::NONE
                },
                data: record.data,
            };
            result.as_data().validate_fixed_size()?;
            out.push(result);
        }
        self.run.now(self.run.bounds.until())?;
        Ok(out)
    }

    fn fetch<'a>(
        &'a mut self,
        name: Vec<u8>,
        kind: u16,
        route: &'a Route,
        depth: usize,
    ) -> FetchFuture<'a> {
        Box::pin(async move {
            if depth >= self.run.shared.limits.depth {
                return Err(Fault::Capacity.into());
            }
            let mut servers = copy_slice(&route.servers)?;
            let mut zone = copy_slice(&route.zone)?;
            let mut recursive = route.recursive;
            let mut referrals = 0;
            let mut unresolved = Vec::new();
            loop {
                self.run.now(self.run.bounds.until())?;
                let mut last = None;
                let mut following = None;
                'candidate: for server in &servers {
                    for _ in 0..self.run.shared.limits.attempts {
                        let reply = match self
                            .run
                            .exchange(
                                &name,
                                kind,
                                *server,
                                &mut self.budget,
                                self.run.bounds.until(),
                                QueryFlags {
                                    recursion_desired: recursive,
                                    dnssec: true,
                                },
                            )
                            .await
                        {
                            Ok(reply) => reply,
                            Err(error) => {
                                if terminal(&error, &self.budget) {
                                    if let Some(old) = last.take() {
                                        self.run.retain(old);
                                    }
                                    return Err(error);
                                }
                                if let Some(old) = last.replace(error) {
                                    self.run.retain(old);
                                }
                                continue;
                            }
                        };
                        if !matches!(reply.code, 0 | 3) {
                            if let Some(old) = last.replace(Error::response_code(reply.code)) {
                                self.run.retain(old);
                            }
                            continue;
                        }
                        let terminal = reply.code == 3
                            || reply.answers.iter().any(|record| {
                                record.class == 1
                                    && ((record.name == name
                                        && (record.kind == kind
                                            || kind == 255
                                            || record.kind == 5))
                                        || (record.kind == 39
                                            && record.name != name
                                            && suffix(&name, &record.name)))
                            })
                            || reply.authority.iter().any(|record| {
                                record.class == 1 && record.kind == 6 && suffix(&name, &record.name)
                            })
                            || (kind == 43
                                && reply.authority.iter().any(|record| {
                                    record.class == 1 && matches!(record.kind, 47 | 50)
                                }));
                        if terminal {
                            if let Some(error) = last {
                                self.run.retain(error);
                            }
                            return Ok(Fetched {
                                reply,
                                server: *server,
                            });
                        }
                        if let Some(referral) = referral(
                            &reply,
                            &name,
                            &zone,
                            self.run.shared.limits.servers,
                            self.run.shared.limits.port,
                        )? {
                            following = Some(referral);
                            break 'candidate;
                        }
                        if let Some(old) = last.replace(Fault::NotFound.into()) {
                            self.run.retain(old);
                        }
                    }
                }
                let Some((next_zone, names, mut addresses)) = following else {
                    if !unresolved.is_empty() {
                        if let Some(old) = last.take() {
                            self.run.retain(old);
                        }
                        servers = self
                            .resolve_names(std::mem::take(&mut unresolved), depth)
                            .await?;
                        continue;
                    }
                    return Err(last.unwrap_or_else(|| Fault::NotFound.into()));
                };
                referrals += 1;
                if referrals >= self.run.shared.limits.depth {
                    return Err(Fault::Capacity.into());
                }
                if let Some(error) = last {
                    self.run.retain(error);
                }
                if addresses.is_empty() {
                    addresses = self.resolve_names(names, depth).await?;
                    unresolved.clear();
                } else {
                    // Try real in-bailiwick glue before spending the same work
                    // on out-of-bailiwick names; retain the latter as fallback.
                    unresolved = names;
                }
                servers = addresses;
                zone = next_zone;
                recursive = false;
                cooperate().await;
            }
        })
    }

    async fn resolve_names(
        &mut self,
        names: Vec<Vec<u8>>,
        depth: usize,
    ) -> Result<Vec<SocketAddr>, Error> {
        if self.run.shared.bootstrap.is_empty() {
            return Err(self.run.shared.unavailable_bootstrap());
        }
        let mut addresses = Vec::new();
        let mut last = None;
        for ns in names {
            if addresses.len() == self.run.shared.limits.servers {
                break;
            }
            // These unauthenticated address results are only routing hints.
            for family in [1, 28] {
                let result = self
                    .run
                    .resolve(
                        super::Question {
                            name: copy_slice(&ns)?,
                            kind: family,
                            recursion_desired: self.run.shared.limits.bootstrap_recursion_desired,
                        },
                        copy_slice(&self.run.shared.bootstrap)?,
                        vec![0],
                        &mut self.budget,
                        depth + 1,
                        self.run.bounds.until(),
                    )
                    .await;
                match result {
                    Ok(records) => {
                        for record in records {
                            if let Some(ip) =
                                address_data(record.record_type.value(), &record.data)?
                            {
                                push_server(
                                    &mut addresses,
                                    SocketAddr::new(ip, self.run.shared.limits.port),
                                    self.run.shared.limits.servers,
                                )?;
                            }
                        }
                    }
                    Err(error) => {
                        if terminal(&error, &self.budget) {
                            if let Some(old) = last.take() {
                                self.run.retain(old);
                            }
                            return Err(error);
                        }
                        if let Some(old) = last.replace(error) {
                            self.run.retain(old);
                        }
                    }
                }
            }
        }
        if addresses.is_empty() {
            return Err(last.unwrap_or_else(|| Fault::NotFound.into()));
        }
        if let Some(error) = last {
            self.run.retain(error);
        }
        Ok(addresses)
    }
}

// Actual verification calls are guarded independently of network polling. A
// synchronous backend call cannot be forcibly interrupted; its result is checked
// against the original native bound before any trust/result is published.
struct Guard<'a> {
    run: &'a Run,
    left: &'a Cell<usize>,
    backend: crypto::Backend,
}
impl Guard<'_> {
    fn before(&self) -> Result<(), Fault> {
        self.run
            .now(self.run.bounds.until())
            .map_err(|error| error.reason())?;
        let left = self.left.get().checked_sub(1).ok_or(Fault::Capacity)?;
        self.left.set(left);
        Ok(())
    }
    fn after(&self) -> Result<(), Fault> {
        self.run
            .now(self.run.bounds.until())
            .map(|_| ())
            .map_err(|error| error.reason())
    }
}
impl core::Crypto for Guard<'_> {
    fn verify(
        &self,
        algorithm: u8,
        key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), Fault> {
        self.before()?;
        self.backend.verify(algorithm, key, message, signature)?;
        self.after()
    }
    fn digest(&self, algorithm: u8, parts: &[&[u8]], output: &mut [u8]) -> Result<usize, Fault> {
        self.before()?;
        let size = self.backend.digest(algorithm, parts, output)?;
        self.after()?;
        Ok(size)
    }
}
impl denial::Sha1 for Guard<'_> {
    fn hash(&mut self, input: &[u8], output: &mut [u8; 20]) -> Result<(), Fault> {
        self.before()?;
        self.backend.hash(input, output)?;
        self.after()
    }
}

struct Group<'a> {
    owner: &'a [u8],
    kind: u16,
    ttl: u32,
    records: Vec<&'a [u8]>,
}
impl Group<'_> {
    fn set(&self) -> Result<Rrset<'_>, Error> {
        Ok(Rrset {
            owner: Name::from_wire(self.owner)?,
            kind: self.kind,
            class: 1,
            ttl: self.ttl,
            records: &self.records,
        })
    }
}
fn groups<'a>(
    records: impl Iterator<Item = &'a OwnedRecord>,
    now: u64,
    maximum: usize,
) -> Result<Vec<Group<'a>>, Error> {
    let mut groups: Vec<Group<'a>> = Vec::new();
    for record in records {
        if record.class != 1 || record.kind == 41 {
            continue;
        }
        let data = record.signed.as_deref().ok_or(Fault::Malformed)?;
        if let Some(group) = groups
            .iter_mut()
            .find(|group| group.owner == record.name && group.kind == record.kind)
        {
            group.ttl = group.ttl.min(ttl(record.expiration, now));
            if !group.records.contains(&data) {
                group.records.try_reserve(1).map_err(Error::allocation)?;
                group.records.push(data);
            }
        } else {
            if groups.len() == maximum {
                return Err(Fault::Capacity.into());
            }
            let mut values = Vec::new();
            values.try_reserve_exact(1).map_err(Error::allocation)?;
            values.push(data);
            groups.try_reserve(1).map_err(Error::allocation)?;
            groups.push(Group {
                owner: &record.name,
                kind: record.kind,
                ttl: ttl(record.expiration, now),
                records: values,
            });
        }
    }
    Ok(groups)
}
fn find<'g, 'a>(groups: &'g [Group<'a>], owner: &[u8], kind: u16) -> Option<&'g Group<'a>> {
    groups
        .iter()
        .find(|group| group.owner == owner && group.kind == kind)
}
struct Workspace {
    message: Vec<u8>,
    record: Vec<u8>,
    order: Vec<usize>,
}
impl Workspace {
    fn new<'g, 'a: 'g>(
        groups: impl Iterator<Item = &'g Group<'a>>,
        maximum: usize,
    ) -> Result<Self, Error> {
        let mut message = 0usize;
        let mut record = 0;
        let mut count = 0;
        for group in groups {
            let mut bytes = 273usize; // longest actual DNS-width RRSIG prefix
            for data in &group.records {
                bytes = bytes
                    .checked_add(group.owner.len() + 10)
                    .and_then(|bytes| bytes.checked_add(data.len()))
                    .ok_or(Fault::Overflow)?;
                record = record.max(data.len());
            }
            message = message.max(bytes);
            count = count.max(group.records.len());
        }
        if message > maximum || record > 65535 {
            return Err(Fault::Capacity.into());
        }
        let mut order = Vec::new();
        order.try_reserve_exact(count).map_err(Error::allocation)?;
        order.resize(count, 0);
        Ok(Self {
            message: zeroes(message)?,
            record: zeroes(record)?,
            order,
        })
    }
    fn scratch(&mut self) -> Scratch<'_> {
        Scratch {
            message: &mut self.message,
            record: &mut self.record,
            order: &mut self.order,
        }
    }
}

fn context<T>(
    run: &Run,
    keys: &Keys,
    reply: Option<&Reply>,
    limits: Limits,
    crypto_left: &Cell<usize>,
    work: &mut denial::Work,
    action: impl FnOnce(
        TrustedKeys<'_>,
        &[Group<'_>],
        &mut Workspace,
        &mut Guard<'_>,
        &mut denial::Work,
        u64,
    ) -> Result<T, Error>,
) -> Result<T, Error> {
    let now = run.now(run.bounds.until())?.as_micros();
    if now >= keys.ds.expires {
        return Err(Fault::Deadline.into());
    }
    let mut key_groups = groups(keys.records.iter(), now, run.shared.limits.records)?;
    let key_index = key_groups
        .iter()
        .position(|group| group.owner == keys.zone && group.kind == 48)
        .ok_or(Fault::Authentication)?;
    key_groups[key_index].ttl = key_groups[key_index].ttl.min(ttl(keys.ds.expires, now));
    let keys_set = &key_groups[key_index];
    let key_signatures = find(&key_groups, &keys.zone, 46).ok_or(Fault::Authentication)?;
    let groups = match reply {
        Some(reply) => groups(
            reply.answers.iter().chain(&reply.authority),
            now,
            run.shared.limits.records,
        )?,
        None => Vec::new(),
    };
    let mut workspace = Workspace::new(key_groups.iter().chain(&groups), limits.scratch_bytes)?;
    let mut backend = Guard {
        run,
        left: crypto_left,
        backend: crypto::Backend,
    };
    let mut ds = Vec::new();
    ds.try_reserve_exact(keys.ds.records.len())
        .map_err(Error::allocation)?;
    for record in &keys.ds.records {
        ds.push(record.as_slice());
    }
    if !ds.iter().any(|record| matches!(record[3], 1 | 2 | 4)) {
        return Err(Fault::Unsupported.into());
    }
    run.native(run.bounds.hard())?;
    let trusted = core::trust_dnskeys(
        Name::from_wire(&keys.zone)?,
        &ds,
        keys_set.set()?,
        key_signatures.set()?,
        serial(now),
        &backend,
        &mut workspace.scratch(),
    )?;
    let after = run.now(run.bounds.until())?.as_micros();
    age(serial(now), serial(after), trusted.ttl())?;
    let result = action(trusted, &groups, &mut workspace, &mut backend, work, now)?;
    run.now(run.bounds.until())?;
    Ok(result)
}
fn verify<'a>(
    keys: TrustedKeys<'a>,
    group: &'a Group<'a>,
    groups: &'a [Group<'a>],
    _now: u64,
    backend: &Guard<'_>,
    workspace: &mut Workspace,
) -> Result<Validated<'a>, Error> {
    let signatures = find(groups, group.owner, 46).ok_or(Fault::Authentication)?;
    let actual = backend.run.now(backend.run.bounds.until())?.as_micros();
    let checked = core::verify_rrset(
        keys,
        group.set()?,
        signatures.set()?,
        serial(actual),
        backend,
        &mut workspace.scratch(),
    )?;
    let after = backend.run.now(backend.run.bounds.until())?.as_micros();
    age(serial(actual), serial(after), checked.ttl())?;
    Ok(checked)
}
fn denial_sets<'a>(
    groups: &'a [Group<'a>],
    keys: TrustedKeys<'a>,
    now: u64,
    backend: &Guard<'_>,
    workspace: &mut Workspace,
) -> Result<Vec<Validated<'a>>, Error> {
    let count = groups
        .iter()
        .filter(|group| matches!(group.kind, 47 | 50))
        .count();
    let mut records = Vec::new();
    records
        .try_reserve_exact(count)
        .map_err(Error::allocation)?;
    for group in groups.iter().filter(|group| matches!(group.kind, 47 | 50)) {
        records.push(verify(keys, group, groups, now, backend, workspace)?);
    }
    Ok(records)
}
#[expect(
    clippy::too_many_arguments,
    reason = "The original trusted keys, clock, proof, crypto and caller scratch/work limits remain explicit independent validation inputs"
)]
fn wildcard_check(
    checked: Validated<'_>,
    groups: &[Group<'_>],
    keys: TrustedKeys<'_>,
    now: u64,
    backend: &mut Guard<'_>,
    workspace: &mut Workspace,
    work: &mut denial::Work,
    limits: Limits,
) -> Result<u32, Error> {
    if !checked.wildcard() {
        return Ok(checked.ttl());
    }
    let records = denial_sets(groups, keys, now, backend, workspace)?;
    let evidence = denial::Evidence::new(
        keys.zone(),
        1,
        &records,
        denial_limits(limits, groups.len()),
        work,
    )?;
    let set = checked.set();
    let proof = denial::positive_wildcard(
        denial::Question {
            name: set.owner,
            kind: set.kind,
            class: set.class,
        },
        &checked,
        &evidence,
        backend,
        work,
    )?;
    if proof.security() != denial::Security::Secure {
        return Err(Fault::Authentication.into());
    }
    Ok(checked.ttl().min(proof.ttl()))
}
fn denial_limits(limits: Limits, records: usize) -> denial::Limits {
    denial::Limits {
        maximum_rrsets: records,
        maximum_records: records,
        maximum_rdata_bytes: 65535,
        maximum_iterations: limits.nsec3_iterations,
    }
}

type Referral = (Vec<u8>, Vec<Vec<u8>>, Vec<SocketAddr>);
fn referral(
    reply: &Reply,
    name: &[u8],
    zone: &[u8],
    maximum: usize,
    port: u16,
) -> Result<Option<Referral>, Error> {
    let closest = reply
        .authority
        .iter()
        .filter(|record| {
            record.class == 1
                && record.kind == 2
                && record.name.len() > zone.len()
                && suffix(name, &record.name)
                && suffix(&record.name, zone)
        })
        .map(|record| record.name.len())
        .max();
    let Some(closest) = closest else {
        return Ok(None);
    };
    let mut names = Vec::new();
    let mut next = None;
    for record in reply.authority.iter().filter(|record| {
        record.class == 1
            && record.kind == 2
            && record.name.len() == closest
            && suffix(name, &record.name)
    }) {
        let target = record.target.as_ref().ok_or(Fault::Malformed)?;
        if !names.contains(target) {
            if names.len() == maximum {
                return Err(Fault::Capacity.into());
            }
            names.try_reserve(1).map_err(Error::allocation)?;
            names.push(copy_slice(target)?);
        }
        if next.is_none() {
            next = Some(copy_slice(&record.name)?);
        }
    }
    let next = next.ok_or(Fault::Malformed)?;
    let mut addresses = Vec::new();
    for ns in &names {
        if suffix(ns, &next) {
            for record in reply
                .additional
                .iter()
                .filter(|record| record.class == 1 && record.name == *ns)
            {
                if let Some(ip) = address(record)? {
                    push_server(&mut addresses, SocketAddr::new(ip, port), maximum)?;
                }
            }
        }
    }
    Ok(Some((next, names, addresses)))
}
fn copy_record(record: &OwnedRecord) -> Result<OwnedRecord, Error> {
    Ok(OwnedRecord {
        signed: record
            .signed
            .as_ref()
            .map(|value| copy_slice(value))
            .transpose()?,
        ttl: record.ttl,
        name: copy_slice(&record.name)?,
        kind: record.kind,
        class: record.class,
        expiration: record.expiration,
        data: copy_slice(&record.data)?,
        target: record
            .target
            .as_ref()
            .map(|value| copy_slice(value))
            .transpose()?,
    })
}
fn check_ds(raw: &[u8]) -> Result<(), Error> {
    if raw.len() < 4 {
        return Err(Fault::Malformed.into());
    }
    let length = match raw[3] {
        1 => 24,
        2 => 36,
        4 => 52,
        _ if raw.len() > 4 => return Ok(()),
        _ => return Err(Fault::Malformed.into()),
    };
    if raw.len() != length {
        return Err(Fault::Malformed.into());
    }
    Ok(())
}
fn ttl(expires: u64, now: u64) -> u32 {
    u32::try_from(expires.saturating_sub(now) / 1_000_000).unwrap_or(u32::MAX)
}
fn expires(now: u64, ttl: u32) -> u64 {
    now.saturating_add(u64::from(ttl) * 1_000_000)
}
fn serial(now: u64) -> u32 {
    (now / 1_000_000) as u32
}
fn age(before: u32, after: u32, lifetime: u32) -> Result<(), Error> {
    let elapsed = after.wrapping_sub(before);
    if elapsed >= 0x8000_0000 || elapsed > lifetime {
        return Err(Fault::Deadline.into());
    }
    Ok(())
}
fn parent_wire(name: &[u8]) -> Result<&[u8], Error> {
    Name::from_wire(name)?;
    if name[0] == 0 {
        return Err(Fault::InvalidInput.into());
    }
    Ok(&name[usize::from(name[0]) + 1..])
}
fn keep_wire_labels(mut name: &[u8], labels: usize) -> Result<&[u8], Error> {
    let count = Name::from_wire(name)?.labels().count();
    if labels > count {
        return Err(Fault::InvalidInput.into());
    }
    for _ in labels..count {
        name = parent_wire(name)?;
    }
    Ok(name)
}
