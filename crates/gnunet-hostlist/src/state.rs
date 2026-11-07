//! Allocated bounded inventory/scheduling. Only explicit verified HELLOs enter it.
use crate::{Advertisement, BODY_BYTES, Error, MIN_CONNECTIONS};
use alloc::{rc::Rc, vec::Vec};
use gnunet_hello::{AbsoluteTime, Hello, SignatureCoverage, SignatureProfile};
use zeroize::Zeroizing;
const SECOND: u64 = 1_000_000;
const HOUR: u64 = 3_600 * SECOND;

/// Active official function selection; each role can be driven independently.
#[derive(Clone, Copy, Debug, Default)]
pub struct Modes {
    /// Bootstrap below the actual CORE connection threshold.
    pub bootstrap: bool,
    /// Test actual received CORE advertisements and remember obtainable URLs.
    pub learning: bool,
    /// Publish the current verified PEERSTORE HELLO inventory over HTTP.
    pub provide: bool,
    /// Advertise the actual configured/bound publication endpoint to new peers.
    pub advertise: bool,
}
/// Explicit metadata/body limits, separate from native HTTP/socket limits.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Configured and learned URI rows combined.
    pub urls: usize,
    /// Maximum accepted learned rows, official default 30.
    pub learned: usize,
    /// Maximum current HELLO identities.
    pub hellos: usize,
    /// Aggregate retained frame and derived URI allocation capacity.
    pub hello_bytes: usize,
    /// Original HTTP-to-PEERSTORE round lifetime in microseconds.
    pub operation_micros: u64,
    /// Maximum complete downloaded body bytes.
    pub body_bytes: usize,
    /// Finite retry-history cap; default covers the bounded 64-peer core client.
    pub max_backoff_micros: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            urls: 64,
            learned: 30,
            hellos: 4096,
            hello_bytes: 4 * BODY_BYTES,
            operation_micros: 60 * SECOND,
            body_bytes: BODY_BYTES,
            max_backoff_micros: 65 * HOUR,
        }
    }
}

/// Immutable URI bytes; clones share one zeroizing allocation. Diagnostics never
/// print URI credentials, query parameters, or path tokens.
#[derive(Clone)]
pub struct Uri(Rc<Zeroizing<Vec<u8>>>);
impl Uri {
    /// Bound and copy a URI after the native URL implementation validates its
    /// scheme/host. This primitive does not pretend to be an HTTP URL parser.
    pub fn copy_from(input: &[u8]) -> Result<Self, Error> {
        Advertisement::new(input)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(input.len())
            .map_err(|_| Error::Capacity)?;
        bytes.extend_from_slice(input);
        Ok(Self(Rc::new(Zeroizing::new(bytes))))
    }
    /// Original immutable URI, potentially sensitive.
    pub fn bytes(&self) -> &[u8] {
        &self.0
    }
}
impl core::fmt::Debug for Uri {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Uri")
            .field("bytes", &self.bytes().len())
            .field("value", &"[redacted]")
            .finish()
    }
}

/// Actual original public CORE advertiser metadata. This is correlation only;
/// the native owner retains the actual CORE epoch and peer-generation token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Advertiser {
    /// Host-local checked source serial, never wire-visible or reused.
    pub source: u64,
    /// Actual CORE peer identity bytes.
    pub peer: [u8; 32],
}
/// Original immutable download allocation. A new HTTP round never reuses it.
#[derive(Clone)]
pub struct Job {
    domain: Rc<()>,
    serial: u64,
}
impl PartialEq for Job {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.domain, &other.domain) && self.serial == other.serial
    }
}
impl Eq for Job {}
impl core::fmt::Debug for Job {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("HostlistJob")
            .field(&Rc::as_ptr(&self.domain))
            .field(&self.serial)
            .finish()
    }
}
/// Original fresh HTTP intent. Completion must use this exact job.
#[derive(Clone, Debug)]
pub struct Fetch {
    /// Original checked allocation.
    pub job: Job,
    /// Frozen actual URL bytes.
    pub uri: Uri,
    /// Original absolute logical deadline, shared by HTTP and HELLO-add phases.
    pub until: u64,
    /// Original advertisement metadata for a test, otherwise configured/known URL.
    pub advertiser: Option<Advertiser>,
    entry: u64,
    testing: bool,
}
/// Actual round observations. Separate local validity from real storage receipts.
#[derive(Clone, Copy, Debug, Default)]
pub struct DownloadOutcome {
    /// HTTP succeeded with complete bounded body and complete frame boundaries.
    pub complete: bool,
    /// Frames passing actual signature/expiry checking under the selected profile.
    pub verified: u32,
    /// Invalid framing, signature, identity, or expiry observations.
    pub invalid: u32,
    /// Actual original PEERSTORE STORE_RESULT with raw GNUNET_OK (1).
    pub stored: u32,
    /// Actual newer HELLO already present after original scan/stop completion.
    pub existing_newer: u32,
    /// Indeterminate/local failed storage operations; never counted as stored.
    pub indeterminate: u32,
}
/// Durable public learned-URL metadata. It does not restore a live HTTP/source,
/// a previous verification result, or authority to reuse an old callback.
#[derive(Clone, Debug)]
pub struct Learned {
    /// Bounded URI; native persistence excludes credential-bearing URLs.
    pub uri: Uri,
    /// Historical bounded quality score.
    pub quality: u64,
    /// Number of historical actual rounds.
    pub times_used: u32,
    /// Original historical logical timestamp, not a current source lease.
    pub created: u64,
    /// Last actual round timestamp.
    pub last_used: u64,
    /// Verified HELLOs observed in last completed round, not stored count.
    pub hello_count: u32,
}
struct Entry {
    serial: u64,
    data: Learned,
    configured: bool,
    accepted: bool,
    persist: bool,
    advertiser: Option<Advertiser>,
}

/// One complete original HELLO, admitted only by actual signature verification.
pub struct HelloFrame {
    peer: [u8; 32],
    expires: u64,
    checked: u64,
    coverage: SignatureCoverage,
    bytes: Vec<u8>,
    uri: Vec<u8>,
}
impl HelloFrame {
    /// Verify exact original bytes using the existing HELLO parser/signature
    /// implementation. The chosen profile's coverage is retained unchanged.
    pub fn verify(
        input: &[u8],
        scratch: &mut [u8],
        limits: gnunet_hello::Limits,
        profile: SignatureProfile,
        now: u64,
    ) -> Result<Self, Error> {
        let parsed = Hello::parse_message(input, None, scratch, limits)?;
        let checked = parsed.verify_at(profile, AbsoluteTime::from_micros(now))?;
        if parsed.expiration().as_micros() <= now {
            return Err(Error::Timeout);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(input.len())
            .map_err(|_| Error::Capacity)?;
        bytes.extend_from_slice(input);
        let length = parsed.url_len()?;
        let mut uri = Vec::new();
        uri.try_reserve_exact(length).map_err(|_| Error::Capacity)?;
        uri.resize(length, 0);
        let actual = parsed.write_url(&mut uri)?.len();
        uri.truncate(actual);
        Ok(Self {
            peer: *parsed.peer().as_bytes(),
            expires: parsed.expiration().as_micros(),
            checked: now,
            coverage: checked.coverage(),
            bytes,
            uri,
        })
    }
    /// Original exact message.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Derived official GNUnet HELLO URI; immutable after the original check.
    pub fn uri(&self) -> &[u8] {
        &self.uri
    }
    fn retained_bytes(&self) -> usize {
        self.bytes.capacity().saturating_add(self.uri.capacity())
    }
    /// Verified public identity.
    pub const fn peer(&self) -> [u8; 32] {
        self.peer
    }
    /// Original signed expiration, not extended by cache/store time.
    pub const fn expires(&self) -> u64 {
        self.expires
    }
    /// Actual check observation time.
    pub const fn checked_at(&self) -> u64 {
        self.checked
    }
    /// Exact signature coverage; MetadataOnly never authenticates addresses.
    pub const fn coverage(&self) -> SignatureCoverage {
        self.coverage
    }
}
impl core::fmt::Debug for HelloFrame {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HelloFrame")
            .field("peer", &self.peer)
            .field("expires", &self.expires)
            .field("coverage", &self.coverage)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// Bounded scheduling and verified inventory; native effects remain caller-owned.
pub struct Core {
    limits: Limits,
    modes: Modes,
    domain: Rc<()>,
    serial: u64,
    entries: Vec<Entry>,
    hellos: Vec<HelloFrame>,
    hello_bytes: usize,
    revision: u64,
    active: Option<Fetch>,
    candidate: Option<Entry>,
    next_check: u64,
    delay: u64,
    learn_after: u64,
    configured_cursor: usize,
    learned_cursor: usize,
    alternate: bool,
    dirty: u64,
}
impl Core {
    /// Reserve all fixed metadata rows. Configured URLs are independent explicit
    /// input and are never implicitly loaded from another process's key/store.
    pub fn new(limits: Limits, modes: Modes, configured: &[Uri], now: u64) -> Result<Self, Error> {
        if limits.urls == 0
            || limits.learned == 0
            || limits.learned > limits.urls
            || configured.len() > limits.urls
            || limits.hellos == 0
            || limits.hello_bytes == 0
            || limits.body_bytes == 0
            || limits.operation_micros == 0
            || limits.max_backoff_micros == 0
            || limits.max_backoff_micros == u64::MAX
            || limits.operation_micros == u64::MAX
            || now == u64::MAX
        {
            return Err(Error::InvalidInput);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(limits.urls)
            .map_err(|_| Error::Capacity)?;
        let mut hellos = Vec::new();
        hellos
            .try_reserve_exact(limits.hellos)
            .map_err(|_| Error::Capacity)?;
        let mut serial = 0u64;
        for uri in configured {
            if entries
                .iter()
                .any(|e: &Entry| e.data.uri.bytes() == uri.bytes())
            {
                continue;
            }
            serial = serial.checked_add(1).ok_or(Error::Overflow)?;
            entries.push(Entry {
                serial,
                data: Learned {
                    uri: uri.clone(),
                    quality: 10_000,
                    times_used: 0,
                    created: now,
                    last_used: 0,
                    hello_count: 0,
                },
                configured: true,
                accepted: true,
                persist: false,
                advertiser: None,
            });
        }
        Ok(Self {
            limits,
            modes,
            domain: Rc::new(()),
            serial,
            entries,
            hellos,
            hello_bytes: 0,
            revision: 0,
            active: None,
            candidate: None,
            next_check: now,
            delay: 0,
            learn_after: now,
            configured_cursor: 0,
            learned_cursor: 0,
            alternate: false,
            dirty: 0,
        })
    }
    /// Pure active function selection.
    pub const fn modes(&self) -> Modes {
        self.modes
    }
    /// Current inventory revision; a snapshot must also respect original expiries.
    pub const fn revision(&self) -> u64 {
        self.revision
    }
    /// Learned-history revision; only an actual worker receipt can call it durable.
    pub const fn learned_revision(&self) -> u64 {
        self.dirty
    }
    /// Borrow only currently valid verified entries. Clock rollback never revives
    /// a physically pruned entry or retags a future check as a past verification.
    pub fn hellos(&self, now: u64) -> impl Iterator<Item = &HelloFrame> {
        self.hellos
            .iter()
            .filter(move |h| h.checked <= now && now < h.expires)
    }
    /// Minimum current cache expiry, including rows not yet physically pruned.
    pub fn next_expiry(&self) -> Option<u64> {
        self.hellos.iter().map(|h| h.expires).min()
    }
    /// Current count, for bounded response preflight.
    pub fn hello_count(&self) -> usize {
        self.hellos.len()
    }
    /// Historical retry interval; this is not a live timer or provider result.
    pub const fn retry_delay(&self) -> u64 {
        self.delay
    }
    /// Restore only historical bounded scheduling metadata before any admission.
    pub fn restore_retry_delay(&mut self, delay: u64) -> Result<(), Error> {
        if self.active.is_some()
            || self.candidate.is_some()
            || delay > self.limits.max_backoff_micros
        {
            return Err(Error::InvalidInput);
        }
        self.delay = delay;
        Ok(())
    }
    /// Remove a peer after an actual empty/deleted monitor record.
    pub fn remove(&mut self, peer: [u8; 32]) -> Result<bool, Error> {
        let Some(index) = self.hellos.iter().position(|h| h.peer == peer) else {
            return Ok(false);
        };
        let revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        let old = self.hellos.swap_remove(index);
        self.hello_bytes = self
            .hello_bytes
            .checked_sub(old.retained_bytes())
            .ok_or(Error::Overflow)?;
        self.revision = revision;
        Ok(true)
    }
    /// Admit one actual newly verified monitor record, atomically against limits.
    pub fn accept(&mut self, frame: HelloFrame, now: u64) -> Result<bool, Error> {
        if frame.checked > now || frame.expires <= now {
            return Err(Error::Stale);
        }
        let old = self.hellos.iter().position(|h| h.peer == frame.peer);
        if old.is_some_and(|i| self.hellos[i].bytes == frame.bytes) {
            return Ok(false);
        }
        let old_bytes = old.map_or(0, |i| self.hellos[i].retained_bytes());
        let charge = self
            .hello_bytes
            .checked_sub(old_bytes)
            .and_then(|n| n.checked_add(frame.retained_bytes()))
            .ok_or(Error::Overflow)?;
        if charge > self.limits.hello_bytes
            || old.is_none() && self.hellos.len() >= self.limits.hellos
        {
            return Err(Error::Capacity);
        }
        let revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        if let Some(i) = old {
            self.hellos[i] = frame
        } else {
            self.hellos.push(frame)
        }
        self.hello_bytes = charge;
        self.revision = revision;
        Ok(true)
    }
    /// Physically forget expired records. It is safe to call without HTTP progress.
    pub fn expire(&mut self, now: u64) -> Result<bool, Error> {
        if !self.hellos.iter().any(|h| h.expires <= now) {
            return Ok(false);
        }
        let revision = self.revision.checked_add(1).ok_or(Error::Overflow)?;
        self.hellos.retain(|h| h.expires > now);
        self.hello_bytes = self.hellos.iter().map(HelloFrame::retained_bytes).sum();
        self.revision = revision;
        Ok(true)
    }
    /// Restore historical public metadata after actual qualified load. No old
    /// provider or signature-check authority is restored. Configured duplicates win.
    pub fn restore(&mut self, data: Learned) -> Result<bool, Error> {
        if self.active.is_some() || self.candidate.is_some() {
            return Err(Error::Conflict);
        }
        if self
            .entries
            .iter()
            .any(|e| e.data.uri.bytes() == data.uri.bytes())
        {
            return Ok(false);
        }
        if self.entries.len() >= self.limits.urls
            || self.entries.iter().filter(|e| !e.configured).count() >= self.limits.learned
        {
            return Err(Error::Capacity);
        }
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        self.entries.push(Entry {
            serial,
            data,
            configured: false,
            accepted: true,
            persist: true,
            advertiser: None,
        });
        self.serial = serial;
        Ok(true)
    }
    /// Accept one original CORE advertisement for an actual HTTP test. `persist`
    /// must be false for a URI containing user credentials; the native URL parser
    /// checks that condition. Tests are rate-limited to one new candidate per 3s.
    pub fn advertise(
        &mut self,
        uri: Uri,
        origin: Advertiser,
        persist: bool,
        now: u64,
    ) -> Result<bool, Error> {
        if !self.modes.learning || now < self.learn_after || self.candidate.is_some() {
            return Ok(false);
        }
        if self
            .entries
            .iter()
            .any(|e| e.data.uri.bytes() == uri.bytes())
        {
            return Ok(false);
        }
        if self.entries.len() >= self.limits.urls && !self.entries.iter().any(|e| !e.configured) {
            return Err(Error::Capacity);
        }
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        self.candidate = Some(Entry {
            serial,
            data: Learned {
                uri,
                quality: 10_000,
                times_used: 0,
                created: now,
                last_used: 0,
                hello_count: 0,
            },
            configured: false,
            accepted: false,
            persist,
            advertiser: Some(origin),
        });
        self.serial = serial;
        self.learn_after = now.saturating_add(3 * SECOND).min(u64::MAX - 1);
        Ok(true)
    }
    /// Prepare one fresh bounded download intent. Native admission is explicit;
    /// call `abandon` if resource reservation fails before any network effect.
    pub fn next(
        &mut self,
        now: u64,
        connections: usize,
        daemon_until: u64,
    ) -> Result<Option<Fetch>, Error> {
        if self.active.is_some() || now >= daemon_until {
            return Ok(None);
        }
        if self.candidate.is_none()
            && (!self.modes.bootstrap || connections >= MIN_CONNECTIONS || now < self.next_check)
        {
            return Ok(None);
        }
        let choice = if self.candidate.is_some() {
            None
        } else {
            let learned = self
                .entries
                .iter()
                .filter(|e| !e.configured && e.accepted)
                .count();
            let use_learned = self.modes.learning && learned != 0 && self.alternate;
            self.alternate = !self.alternate;
            let count = self
                .entries
                .iter()
                .filter(|e| e.accepted && e.configured != use_learned)
                .count();
            if count == 0 {
                self.entries.iter().position(|e| e.accepted)
            } else {
                let cursor = if use_learned {
                    &mut self.learned_cursor
                } else {
                    &mut self.configured_cursor
                };
                let target = *cursor % count;
                *cursor = cursor.wrapping_add(1);
                self.entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| e.accepted && e.configured != use_learned)
                    .nth(target)
                    .map(|(i, _)| i)
            }
        };
        let delay = self.delay;
        self.delay = if self.delay == 0 {
            SECOND
        } else {
            self.delay.saturating_mul(2)
        }
        .min(
            HOUR.saturating_mul(
                u64::try_from(connections)
                    .unwrap_or(u64::MAX)
                    .saturating_add(1),
            ),
        )
        .min(self.limits.max_backoff_micros)
        .min(u64::MAX - 1);
        self.next_check = now.saturating_add(delay.max(SECOND)).min(u64::MAX - 1);
        let entry = if let Some(candidate) = &self.candidate {
            candidate
        } else if let Some(index) = choice {
            &self.entries[index]
        } else {
            return Ok(None);
        };
        let serial = self.serial.checked_add(1).ok_or(Error::Overflow)?;
        let fetch = Fetch {
            job: Job {
                domain: self.domain.clone(),
                serial,
            },
            uri: entry.data.uri.clone(),
            until: now
                .saturating_add(self.limits.operation_micros)
                .min(daemon_until)
                .min(u64::MAX - 1),
            advertiser: entry.advertiser,
            entry: entry.serial,
            testing: !entry.accepted,
        };
        self.serial = serial;
        self.active = Some(fetch.clone());
        Ok(Some(fetch))
    }
    /// Abandon only a never-admitted original provider intent; no quality success.
    pub fn abandon(&mut self, job: &Job) -> Result<(), Error> {
        if self.active.as_ref().is_none_or(|f| &f.job != job) {
            return Err(Error::Stale);
        }
        self.active = None;
        Ok(())
    }
    /// Consume actual final observations from the original HTTP/HELLO-add job.
    pub fn finish(&mut self, job: &Job, outcome: DownloadOutcome, now: u64) -> Result<(), Error> {
        let fetch = self
            .active
            .as_ref()
            .filter(|f| &f.job == job)
            .ok_or(Error::Stale)?;
        let testing = fetch.testing;
        let serial = fetch.entry;
        let valid = outcome.complete && outcome.invalid == 0;
        let dirty = self.dirty.checked_add(1).ok_or(Error::Overflow)?;
        if testing {
            if self.candidate.as_ref().is_none_or(|e| e.serial != serial) {
                return Err(Error::Stale);
            }
            if valid {
                let full = self.entries.len() >= self.limits.urls
                    || self.entries.iter().filter(|e| !e.configured).count() >= self.limits.learned;
                let replace = if full {
                    Some(
                        self.entries
                            .iter()
                            .enumerate()
                            .filter(|(_, e)| !e.configured)
                            .min_by_key(|(_, e)| e.data.quality)
                            .map(|(i, _)| i)
                            .ok_or(Error::Capacity)?,
                    )
                } else {
                    None
                };
                let mut entry = self.candidate.take().ok_or(Error::Stale)?;
                entry.accepted = true;
                entry.advertiser = None;
                entry.data.times_used = 1;
                entry.data.last_used = now;
                entry.data.hello_count = outcome.verified;
                entry.data.quality = entry
                    .data
                    .quality
                    .saturating_add(100 + u64::from(outcome.verified));
                if let Some(index) = replace {
                    self.entries[index] = entry
                } else {
                    self.entries.push(entry)
                }
            } else {
                self.candidate = None;
            }
        } else {
            let index = self
                .entries
                .iter()
                .position(|e| e.serial == serial)
                .ok_or(Error::Stale)?;
            let entry = &mut self.entries[index];
            entry.data.times_used = entry.data.times_used.saturating_add(1);
            entry.data.last_used = now;
            entry.data.hello_count = outcome.verified;
            entry.data.quality = if valid {
                entry
                    .data
                    .quality
                    .saturating_add(100 + u64::from(outcome.verified))
            } else {
                entry.data.quality.saturating_sub(100)
            };
        }
        self.active = None;
        self.dirty = dirty;
        Ok(())
    }
    /// Borrow only accepted, credential-free learned metadata for persistence.
    pub fn learned(&self) -> impl Iterator<Item = &Learned> {
        self.entries
            .iter()
            .filter(|e| !e.configured && e.accepted && e.persist)
            .map(|e| &e.data)
    }
    /// Retire a failed original job without a coherent current clock. No success,
    /// new timestamp, or new provider/source authority is manufactured.
    pub fn retire_without_time(&mut self, job: &Job) -> Result<(), Error> {
        let fetch = self
            .active
            .as_ref()
            .filter(|f| &f.job == job)
            .ok_or(Error::Stale)?;
        let serial = fetch.entry;
        let testing = fetch.testing;
        let dirty = self.dirty.checked_add(1).ok_or(Error::Overflow)?;
        if testing {
            self.candidate = None
        } else if let Some(entry) = self.entries.iter_mut().find(|e| e.serial == serial) {
            entry.data.quality = entry.data.quality.saturating_sub(100);
            entry.data.times_used = entry.data.times_used.saturating_add(1)
        }
        self.active = None;
        self.dirty = dirty;
        Ok(())
    }
    /// Next original scheduling boundary, excluding caller-owned in-flight IO.
    pub fn next_check(&self) -> u64 {
        self.next_check
    }
    /// Configured native body cap.
    pub const fn body_limit(&self) -> usize {
        self.limits.body_bytes
    }
}
