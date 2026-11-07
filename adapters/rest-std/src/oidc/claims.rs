//! Official normal/aggregated claim shapes. JWT presentations remain opaque;
//! the relying party verifies their issuer/signature rather than this parser.
use super::*;
use gnunet_reclaim::{Attribute, CredentialType};
struct Requested {
    name: Zeroizing<Vec<u8>>,
    idtoken: bool,
    userinfo: bool,
}
pub(super) struct Selection {
    scope: Zeroizing<Vec<u8>>,
    names: Vec<Requested>,
}
const PROFILE: &[&[u8]] = &[
    b"name",
    b"family_name",
    b"given_name",
    b"middle_name",
    b"nickname",
    b"preferred_username",
    b"profile",
    b"picture",
    b"website",
    b"gender",
    b"birthdate",
    b"zoneinfo",
    b"locale",
    b"updated_at",
];
const EMAIL: &[&[u8]] = &[b"email", b"email_verified"];
const PHONE: &[&[u8]] = &[b"phone_number", b"phone_number_verified"];
const ADDRESS: &[&[u8]] = &[
    b"street_address",
    b"locality",
    b"region",
    b"postal_code",
    b"country",
];
impl Selection {
    pub(super) fn new(request: &OwnedRequest, limits: crate::Limits) -> Result<Self, Error> {
        let scope = required(request, b"scope", limits.bytes)?;
        // RFC6749 scope tokens use visible ASCII except quote/backslash, with
        // literal spaces separating tokens. GNUnet additionally selects an
        // attribute by an exact nonstandard scope name; it has no fixed allowlist.
        if scope
            .iter()
            .any(|b| !matches!(b, b' ' | 0x21 | 0x23..=0x5b | 0x5d..=0x7e))
        {
            return Err(oauth(400, "invalid_scope", "Invalid scope token bytes"));
        }
        if !scope.split(|b| *b == b' ').any(|s| s == b"openid") {
            return Err(oauth(400, "invalid_scope", "Scope must include openid"));
        }
        let mut names: Vec<Requested> = Vec::new();
        names
            .try_reserve_exact(limits.items)
            .map_err(|_| Fault::Capacity)?;
        if let Some(input) = request.parameter(b"claims", limits.bytes)? {
            parse(&input, limits.json, |root| {
                for member in root.members()? {
                    let group = decoded(member.name)?;
                    if group.as_slice() != b"id_token" && group.as_slice() != b"userinfo" {
                        continue;
                    }
                    for member in member.value.members()? {
                        let name = decoded(member.name)?;
                        // The pinned producer selects names only. Parsed claim values,
                        // including essential/value/values, do not add constraints.
                        if let Some(old) = names
                            .iter_mut()
                            .find(|n| n.name.as_slice() == name.as_slice())
                        {
                            old.idtoken |= group.as_slice() == b"id_token";
                            old.userinfo |= group.as_slice() == b"userinfo";
                        } else {
                            if names.len() == limits.items {
                                return Err(Fault::Capacity.into());
                            }
                            names.push(Requested {
                                name,
                                idtoken: group.as_slice() == b"id_token",
                                userinfo: group.as_slice() == b"userinfo",
                            })
                        }
                    }
                }
                Ok(())
            })?;
        }
        Ok(Self { scope, names })
    }
    fn flags(&self, name: &[u8]) -> (bool, bool) {
        let scoped = self.scope.split(|b| *b == b' ').any(|scope| match scope {
            b"profile" => PROFILE.contains(&name),
            b"email" => EMAIL.contains(&name),
            b"phone" => PHONE.contains(&name),
            b"address" => name == b"address" || ADDRESS.contains(&name),
            b"openid" | b"" => false,
            _ => scope == name,
        });
        let explicit = self.names.iter().find(|r| r.name.as_slice() == name);
        (
            scoped || explicit.is_some_and(|r| r.idtoken),
            scoped || explicit.is_some_and(|r| r.userinfo),
        )
    }
}
pub(super) struct Collected {
    pub all: Zeroizing<Vec<u8>>,
    pub idtoken: Zeroizing<Vec<u8>>,
}
impl<I: gnunet_dns::Idna> Context<'_, I> {
    pub(super) async fn oidc_attributes(
        &self,
        key: gnunet_wire::official::identity::SecretKeyView<'_>,
        selection: &Selection,
        until: u64,
        hard: Instant,
    ) -> Result<Collected, Error> {
        let mut all = bytes(self.limits.bytes)?;
        let mut idtoken = bytes(self.limits.bytes)?;
        let (mut used, mut token_used, mut count) = (0usize, 0usize, 0usize);
        let mut iterator = Iterator::new(
            self.instances.reclaim,
            self.sources.reclaim.duplicate()?,
            key,
            ipc::Iteration::Attributes,
            until,
            self.limits.reclaim,
        )?;
        loop {
            match poll_fn(|cx| iterator.poll(cx, Some(hard))).await? {
                Progress::Item { reply, .. } => {
                    let item = match reply.view()? {
                        ipc::Response::Attribute {
                            attribute: Some(item),
                            ..
                        } => item,
                        _ => return Err(Fault::Malformed.into()),
                    };
                    let (id, user) = selection.flags(item.name.bytes());
                    if id || user {
                        if count >= self.limits.items {
                            return Err(Fault::Capacity.into());
                        }
                        let previous = AttributeList::new(&all[..used], ListLimits::IPC)?;
                        if previous
                            .iter()
                            .any(|a| a.name.bytes() == item.name.bytes() || a.id == item.id)
                        {
                            return Err(Fault::Conflict.into());
                        }
                        let n = item.encoded_len()?;
                        let end = used.checked_add(n).ok_or(Fault::Overflow)?;
                        item.encode(all.get_mut(used..end).ok_or(Fault::Capacity)?)?;
                        used = end;
                        if id {
                            let end = token_used.checked_add(n).ok_or(Fault::Overflow)?;
                            item.encode(idtoken.get_mut(token_used..end).ok_or(Fault::Capacity)?)?;
                            token_used = end;
                        }
                        count += 1;
                    }
                    iterator.next(until)?;
                }
                Progress::Completed(c) => {
                    if let Outcome::Local { reason, submission } = c.outcome {
                        return Err(Error::ReclaimRetired { reason, submission });
                    }
                    all.truncate(used);
                    idtoken.truncate(token_used);
                    return Ok(Collected { all, idtoken });
                }
                Progress::Lost { cause, .. } => return Err(Error::ReclaimSource(cause)),
                Progress::Unavailable(error) => return Err(Error::Native(error)),
                Progress::ConnectRetry { error, .. } => return Err(Error::Io(error)),
                Progress::Closed => return Err(Error::SourceLost),
                Progress::WaitDeadline => return Err(Error::Deadline),
                _ => {}
            }
        }
    }
}
pub(super) struct Token<'a> {
    pub audience: &'a [u8],
    pub nonce: &'a [u8],
    pub now: u64,
    pub expires: u64,
}
fn reserved(name: &[u8]) -> bool {
    [
        b"iss".as_slice(),
        b"sub",
        b"aud",
        b"iat",
        b"nbf",
        b"exp",
        b"nonce",
        b"_claim_names",
        b"_claim_sources",
    ]
    .contains(&name)
}
fn source_name(index: usize, json: &mut Json) -> Result<(), Error> {
    let mut name = Json::new(32)?;
    name.raw(b"src")?;
    name.number(u64::try_from(index).map_err(|_| Fault::Overflow)?)?;
    json.string(&name.bytes)
}
pub(super) fn payload(
    attrs: AttributeList<'_>,
    presentations: PresentationList<'_>,
    subject: ZoneKey,
    origin: &[u8],
    token: Option<Token<'_>>,
    cap: usize,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    for (n, a) in attrs.iter().enumerate() {
        if reserved(a.name.bytes())
            || attrs
                .iter()
                .take(n)
                .any(|b| b.name.bytes() == a.name.bytes())
        {
            return Err(Fault::Conflict.into());
        }
    }
    // Official aggregation preserves presentation indices, including unused
    // entries. Missing presentations contribute no attested claim.
    for p in presentations.iter() {
        if p.kind != CredentialType::JWT {
            return Err(Fault::Unsupported.into());
        }
    }
    let address = attrs.iter().find_map(|a| {
        if !ADDRESS.contains(&a.name.bytes()) {
            return None;
        }
        if a.credential.is_zero() {
            Some(None)
        } else {
            presentations
                .iter()
                .position(|p| p.credential == a.credential)
                .map(Some)
        }
    });
    let mut json = Json::new(cap)?;
    json.raw(b"{\"iss\":")?;
    json.string(origin)?;
    json.raw(b",\"sub\":")?;
    json.string(&public_text(subject)?)?;
    if let Some(token) = token {
        json.raw(b",\"aud\":")?;
        json.string(token.audience)?;
        for (key, value) in [
            (b"iat".as_slice(), token.now / 1_000_000),
            (b"nbf", token.now / 1_000_000),
            (b"exp", token.expires / 1_000_000),
        ] {
            json.raw(b",")?;
            json.string(key)?;
            json.raw(b":")?;
            json.number(value)?
        }
        if !token.nonce.is_empty() {
            json.raw(b",\"nonce\":")?;
            json.string(token.nonce)?
        }
    }
    for a in attrs
        .iter()
        .filter(|a| a.credential.is_zero() && !ADDRESS.contains(&a.name.bytes()))
    {
        json.raw(b",")?;
        json.string(a.name.bytes())?;
        json.raw(b":")?;
        normal_value(a, &mut json)?
    }
    if address == Some(None) {
        if attrs.iter().any(|a| a.name.bytes() == b"address") {
            return Err(Fault::Conflict.into());
        }
        json.raw(b",\"address\":{")?;
        let mut first = true;
        for a in attrs
            .iter()
            .filter(|a| a.credential.is_zero() && ADDRESS.contains(&a.name.bytes()))
        {
            if !first {
                json.raw(b",")?
            }
            first = false;
            json.string(a.name.bytes())?;
            json.raw(b":")?;
            normal_value(a, &mut json)?
        }
        json.raw(b"}")?;
    }
    if presentations.iter().next().is_some() {
        json.raw(b",\"_claim_names\":{")?;
        let mut first = true;
        let mut address_emitted = false;
        for a in attrs.iter().filter(|a| !a.credential.is_zero()) {
            let Some(index) = presentations
                .iter()
                .position(|p| p.credential == a.credential)
            else {
                continue;
            };
            let name = if ADDRESS.contains(&a.name.bytes()) {
                if address_emitted || address != Some(Some(index)) {
                    continue;
                }
                address_emitted = true;
                b"address".as_slice()
            } else {
                a.name.bytes()
            };
            if !first {
                json.raw(b",")?
            }
            first = false;
            json.string(name)?;
            json.raw(b":")?;
            source_name(index, &mut json)?
        }
        json.raw(b"},\"_claim_sources\":{")?;
        let mut first = true;
        for (n, p) in presentations.iter().enumerate() {
            if !first {
                json.raw(b",")?
            }
            first = false;
            source_name(n, &mut json)?;
            json.raw(b":{\"JWT\":")?;
            json.string(
                gnunet_reclaim_credentials::credential_value_string(p.kind, p.value)?.expose(),
            )?;
            json.raw(b"}")?
        }
        json.raw(b"}")?;
    }
    json.raw(b"}")?;
    Ok(json.bytes)
}
fn normal_value(attribute: Attribute<'_>, json: &mut Json) -> Result<(), Error> {
    let value =
        gnunet_reclaim_credentials::attribute_value_string(attribute.kind, attribute.value)?
            .expose();
    // OIDC externally requires booleans/integer for these standard claims. Source
    // C emits strings for every BASIC attribute; canonical Rust preserves meaning.
    match attribute.name.bytes() {
        b"address" => {
            parse(
                value,
                gnunet_json::Limits {
                    bytes: value.len(),
                    nodes: 4096,
                    depth: 64,
                    work: 8_388_608,
                },
                |root| {
                    if root.kind() == gnunet_json::ValueKind::Object {
                        Ok(())
                    } else {
                        Err(Fault::Malformed.into())
                    }
                },
            )?;
            json.raw(value)
        }
        b"email_verified" | b"phone_number_verified" => match value {
            b"true" | b"yes" | b"1" => json.boolean(true),
            b"false" | b"no" | b"0" => json.boolean(false),
            _ => Err(Fault::Malformed.into()),
        },
        b"updated_at" => {
            let mut n = 0u64;
            if value.is_empty() {
                return Err(Fault::Malformed.into());
            }
            for b in value {
                if !b.is_ascii_digit() {
                    return Err(Fault::Malformed.into());
                }
                n = n
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(u64::from(b - b'0')))
                    .ok_or(Fault::Overflow)?;
            }
            i64::try_from(n).map_err(|_| Fault::Overflow)?;
            json.number(n)
        }
        _ => json.string(value),
    }
}
