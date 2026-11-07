//! Bounded private Rust snapshot schema, independent from every GNUnet wire
//! message/C JWK layout. Sessions, reservations and HTTP/native jobs are absent.
use super::*;
const MAGIC: &[u8; 8] = b"RSTOID02";
trait Sink {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Fault>;
}
struct Measure(usize);
impl Sink for Measure {
    fn put(&mut self, b: &[u8]) -> Result<(), Fault> {
        self.0 = self.0.checked_add(b.len()).ok_or(Fault::Overflow)?;
        Ok(())
    }
}
struct Output {
    bytes: Zeroizing<Vec<u8>>,
    cap: usize,
}
impl Sink for Output {
    fn put(&mut self, b: &[u8]) -> Result<(), Fault> {
        if self
            .bytes
            .len()
            .checked_add(b.len())
            .is_none_or(|n| n > self.cap)
        {
            return Err(Fault::Capacity);
        }
        self.bytes.extend_from_slice(b);
        Ok(())
    }
}
fn u32_to(out: &mut impl Sink, v: usize) -> Result<(), Fault> {
    out.put(&u32::try_from(v).map_err(|_| Fault::Overflow)?.to_be_bytes())
}
fn blob(out: &mut impl Sink, b: &[u8]) -> Result<(), Fault> {
    u32_to(out, b.len())?;
    out.put(b)
}
fn selected_grant<'a>(
    state: &'a State,
    change: Option<&'a Change>,
    row: usize,
) -> Option<&'a Grant> {
    match change {
        Some(Change::Issue { row: r, grant, .. }) if *r == row => Some(grant),
        Some(Change::Exchange { row: r, .. }) if *r == row => None,
        _ => state.grants[row].as_ref(),
    }
}
fn selected_access<'a>(
    state: &'a State,
    change: Option<&'a Change>,
    row: usize,
) -> Option<&'a Access> {
    match change {
        Some(Change::Exchange {
            access_row: r,
            access,
            ..
        }) if *r == row => Some(access),
        _ => state.accesses[row].as_ref(),
    }
}
#[derive(Clone, Copy)]
struct Moment {
    now: u64,
    wall: u64,
    native: Instant,
}
fn write(
    provider: &Provider,
    state: &State,
    material: &Material,
    change: Option<&Change>,
    moment: Moment,
    out: &mut impl Sink,
) -> Result<(), Fault> {
    let Moment { now, wall, native } = moment;
    out.put(MAGIC)?;
    out.put(&u32::from(material.tag).to_be_bytes())?;
    out.put(&state.next.to_be_bytes())?;
    out.put(&now.to_be_bytes())?;
    out.put(&wall.to_be_bytes())?;
    blob(out, &provider.origin)?;
    blob(out, &provider.login_ui)?;
    blob(
        out,
        provider
            .client_secret
            .as_deref()
            .map(Vec::as_slice)
            .unwrap_or(&[]),
    )?;
    blob(out, &material.key)?;
    let grants = (0..state.grants.len())
        .filter_map(|i| selected_grant(state, change, i))
        .filter(|g| {
            g.bound.until > now
                && g.bound.hard > native
                && matches!(g.state, GrantState::Issued { .. })
        })
        .count();
    let accesses = (0..state.accesses.len())
        .filter_map(|i| selected_access(state, change, i))
        .filter(|a| a.bound.until > now && a.bound.hard > native)
        .count();
    u32_to(out, grants)?;
    u32_to(out, accesses)?;
    for i in 0..state.grants.len() {
        let Some(g) = selected_grant(state, change, i)
            .filter(|g| g.bound.until > now && g.bound.hard > native)
        else {
            continue;
        };
        let GrantState::Issued {
            code,
            client,
            redirect,
            subject,
        } = &g.state
        else {
            continue;
        };
        out.put(&g.serial.to_be_bytes())?;
        out.put(&g.bound.until.to_be_bytes())?;
        out.put(&g.bound.wall_until.to_be_bytes())?;
        out.put(&subject.to_wire())?;
        blob(out, code)?;
        blob(out, client)?;
        blob(out, redirect)?;
    }
    for i in 0..state.accesses.len() {
        let Some(a) = selected_access(state, change, i)
            .filter(|a| a.bound.until > now && a.bound.hard > native)
        else {
            continue;
        };
        out.put(&a.bound.until.to_be_bytes())?;
        out.put(&a.bound.wall_until.to_be_bytes())?;
        out.put(&a.subject.to_wire())?;
        blob(out, &a.token)?;
    }
    Ok(())
}
pub(super) fn encode(
    provider: &Provider,
    material: &Material,
    change: Option<&Change>,
    max: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let state = provider.state.borrow();
    let now = provider
        .clock
        .sample()
        .map_err(Error::Clock)?
        .now
        .as_micros();
    let wall = wall_now()?;
    let native = Instant::now();
    let mut measure = Measure(0);
    write(
        provider,
        &state,
        material,
        change,
        Moment { now, wall, native },
        &mut measure,
    )?;
    if measure.0 > max {
        return Err(Fault::Capacity.into());
    }
    let mut raw = Vec::new();
    raw.try_reserve_exact(measure.0)
        .map_err(|_| Fault::Capacity)?;
    let mut output = Output {
        bytes: Zeroizing::new(raw),
        cap: measure.0,
    };
    write(
        provider,
        &state,
        material,
        change,
        Moment { now, wall, native },
        &mut output,
    )?;
    if output.bytes.len() != measure.0 {
        return Err(Fault::Conflict.into());
    }
    Ok(output.bytes)
}
struct Reader<'a> {
    tail: &'a [u8],
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], Fault> {
        let v = self.tail.get(..n).ok_or(Fault::Truncated)?;
        self.tail = &self.tail[n..];
        Ok(v)
    }
    fn u32(&mut self) -> Result<usize, Fault> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| Fault::Truncated)?) as usize)
    }
    fn u64(&mut self) -> Result<u64, Fault> {
        Ok(u64::from_be_bytes(
            self.take(8)?.try_into().map_err(|_| Fault::Truncated)?,
        ))
    }
    fn blob(&mut self, cap: usize) -> Result<&'a [u8], Fault> {
        let n = self.u32()?;
        if n > cap {
            return Err(Fault::Capacity);
        }
        self.take(n)
    }
}
fn recover_bound(
    until: u64,
    wall_until: u64,
    now: u64,
    wall: u64,
    anchor: Instant,
) -> Result<Option<Bound>, Fault> {
    if until == u64::MAX || wall_until == u64::MAX {
        return Err(Fault::Malformed);
    }
    if until <= now || wall_until <= wall {
        return Ok(None);
    }
    let remaining = (until - now).min(wall_until - wall);
    Ok(Some(Bound {
        until,
        wall_until,
        hard: anchor
            .checked_add(Duration::from_micros(remaining))
            .ok_or(Fault::Overflow)?,
    }))
}
fn import(source: &KeySource, key: &[u8], tag: u8) -> Result<Signer, Fault> {
    match (source, tag) {
        (KeySource::Rs256 { bits, limits }, 1) => {
            let key = gnunet_oidc_crypto_host::Rsa::from_pkcs8(key, *limits)?;
            if key.signature_bytes().checked_mul(8) != Some(*bits) {
                return Err(Fault::Conflict);
            }
            Ok(Signer::Rs256(key))
        }
        (KeySource::Hs512 { secret, limits }, 2) => {
            if !equal(secret, key) {
                return Err(Fault::Authentication);
            }
            Ok(Signer::Hs512(gnunet_oidc_crypto_host::Hs512::new(
                key, *limits,
            )?))
        }
        _ => Err(Fault::Conflict),
    }
}
fn fresh(source: &KeySource) -> Result<(Signer, Material), Error> {
    match source {
        KeySource::Rs256 { bits, limits } => {
            let key = gnunet_oidc_crypto_host::Rsa::generate(*bits, *limits)?;
            let material = Material {
                tag: 1,
                key: key.export_pkcs8()?,
            };
            Ok((Signer::Rs256(key), material))
        }
        KeySource::Hs512 { secret, limits } => {
            let signer = Signer::Hs512(gnunet_oidc_crypto_host::Hs512::new(secret, *limits)?);
            Ok((
                signer,
                Material {
                    tag: 2,
                    key: copy(secret)?,
                },
            ))
        }
    }
}
pub(super) fn recover(
    body: &[u8],
    options: &Options<'_>,
    now: u64,
    wall: u64,
    anchor: Instant,
) -> Result<(Signer, Material, Option<State>), Error> {
    if body.is_empty() {
        let (s, m) = fresh(&options.signer)?;
        return Ok((s, m, None));
    }
    if body.len() > options.snapshot_bytes {
        return Err(Fault::Capacity.into());
    }
    let mut r = Reader { tail: body };
    if r.take(8)? != MAGIC {
        return Err(Fault::Authentication.into());
    }
    let tag = u8::try_from(r.u32()?).map_err(|_| Fault::Malformed)?;
    let next = r.u64()?;
    let floor = r.u64()?;
    let wall_floor = r.u64()?;
    if next == 0 || now < floor || wall < wall_floor {
        return Err(Fault::TimeUncertain.into());
    }
    if r.blob(4096)? != options.origin
        || r.blob(4096)? != options.login_ui
        || !equal(r.blob(4096)?, options.client_secret.unwrap_or(&[]))
    {
        return Err(Fault::Conflict.into());
    }
    let key_limit = match &options.signer {
        KeySource::Rs256 { limits, .. } | KeySource::Hs512 { limits, .. } => limits.key_bytes,
    };
    let material = Material {
        tag,
        key: copy(r.blob(key_limit)?)?,
    };
    let signer = import(&options.signer, &material.key, tag)?;
    let grants = r.u32()?;
    let accesses = r.u32()?;
    if grants > options.limits.grants || accesses > options.limits.accesses {
        return Err(Fault::Capacity.into());
    }
    let mut state = State {
        sessions: slots(options.limits.sessions)?,
        grants: slots(options.limits.grants)?,
        accesses: slots(options.limits.accesses)?,
        next,
    };
    let mut bytes = 0usize;
    for row in 0..grants {
        let serial = r.u64()?;
        let until = r.u64()?;
        let wall_until = r.u64()?;
        let subject = ZoneKey::from_wire(r.take(36)?)?;
        if serial == 0 || serial >= next {
            return Err(Fault::Malformed.into());
        }
        let code = r.blob(
            options
                .limits
                .code
                .bytes
                .checked_mul(2)
                .ok_or(Fault::Overflow)?,
        )?;
        let client = r.blob(options.limits.bytes)?;
        let redirect = r.blob(options.limits.bytes)?;
        Uri::new(client)?;
        Uri::new(redirect)?;
        if code.is_empty() || client.is_empty() || redirect.is_empty() {
            return Err(Fault::Malformed.into());
        }
        bytes = bytes
            .checked_add(code.len())
            .and_then(|n| n.checked_add(client.len()))
            .and_then(|n| n.checked_add(redirect.len()))
            .ok_or(Fault::Overflow)?;
        if bytes > options.limits.bytes {
            return Err(Fault::Capacity.into());
        }
        if let Some(bound) = recover_bound(until, wall_until, now, wall, anchor)? {
            state.grants[row] = Some(Grant {
                serial,
                bound,
                state: GrantState::Issued {
                    code: copy(code)?,
                    client: copy(client)?,
                    redirect: copy(redirect)?,
                    subject,
                },
            });
        }
    }
    for row in 0..accesses {
        let until = r.u64()?;
        let wall_until = r.u64()?;
        let subject = ZoneKey::from_wire(r.take(36)?)?;
        let token = r.blob(options.limits.bytes)?;
        if token.is_empty() {
            return Err(Fault::Malformed.into());
        }
        bytes = bytes.checked_add(token.len()).ok_or(Fault::Overflow)?;
        if bytes > options.limits.bytes {
            return Err(Fault::Capacity.into());
        }
        if let Some(bound) = recover_bound(until, wall_until, now, wall, anchor)? {
            state.accesses[row] = Some(Access {
                bound,
                token: copy(token)?,
                subject,
            });
        }
    }
    if !r.tail.is_empty() {
        return Err(Fault::Malformed.into());
    }
    // Reorder only new process-local row slots, moving owners without cloning
    // secret payloads. This makes duplicate checks O(total bytes * log rows).
    state.grants.sort_unstable_by(|a, b| match (a, b) {
        (Some(a), Some(b)) => match (&a.state, &b.state) {
            (GrantState::Issued { code: a, .. }, GrantState::Issued { code: b, .. }) => {
                a.as_slice().cmp(b.as_slice())
            }
            _ => std::cmp::Ordering::Equal,
        },
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
    });
    if state.grants.windows(2).any(|w|match(&w[0],&w[1]){(Some(a),Some(b))=>matches!((&a.state,&b.state),(GrantState::Issued{code:a,..},GrantState::Issued{code:b,..})if equal(a,b)),_=>false}){return Err(Fault::Conflict.into());}
    state.accesses.sort_unstable_by(|a, b| {
        a.as_ref()
            .map(|a| a.token.as_slice())
            .cmp(&b.as_ref().map(|b| b.token.as_slice()))
    });
    if state
        .accesses
        .windows(2)
        .any(|w| matches!((&w[0],&w[1]),(Some(a),Some(b))if equal(&a.token,&b.token)))
    {
        return Err(Fault::Conflict.into());
    }
    Ok((signer, material, Some(state)))
}
