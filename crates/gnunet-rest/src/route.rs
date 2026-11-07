//! Actual built-in v0.29.1 REST namespaces. Routing performs no service work.
//! Unknown/unsupported methods remain explicit; constants are not fake handlers.
use crate::http::Request;
use gnunet_types::Error;
/// Built or conditional official plugin namespace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Family {
    /// /identity and the actual /sign route.
    Identity,
    /// /namestore (including /namestore/import).
    Namestore,
    /// /reclaim active attributes/credential/tickets/revoke/consume routes.
    Reclaim,
    /// Actual static /copying information.
    Copying,
    /// /config, not implicitly wired to a file or private configuration owner.
    Config,
    /// /gns, executed only through an explicit existing native query endpoint.
    Gns,
    /// Optional JOSE-built /openid and discovery.
    Openid,
}
/// One actual official method/namespace contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Endpoint {
    /// GET `/identity`.
    Identities,
    /// GET `/identity/name/<name>`.
    IdentityName,
    /// GET `/identity/pubkey/<base32>`.
    IdentityPublic,
    /// POST `/identity`.
    IdentityCreate,
    /// PUT `/identity/name/<name>`.
    IdentityRenameName,
    /// PUT `/identity/pubkey/<base32>`.
    IdentityRenamePublic,
    /// DELETE `/identity/name/<name>`.
    IdentityDeleteName,
    /// DELETE `/identity/pubkey/<base32>`.
    IdentityDeletePublic,
    /// GET `/sign?user=...&data=..`., requires the raw EdDSA signing capability.
    IdentitySign,
    /// GET `/namestore/<ego>[/<label>]`.
    Names,
    /// POST `/namestore/<ego>`, actual lookup then append/store.
    NameAppend,
    /// PUT `/namestore/<ego>`, actual replace/store.
    NameReplace,
    /// DELETE `/namestore/<ego>/<label>`.
    NameDelete,
    /// POST `/namestore/import/<ego>`, actual finite complete record-set batch.
    NameImport,
    /// GET `/reclaim/attributes/<ego>`.
    Attributes,
    /// POST `/reclaim/attributes/<ego>`.
    AttributeStore,
    /// DELETE `/reclaim/attributes/<ego>/<base32id>`.
    AttributeDelete,
    /// GET `/reclaim/credential/<ego>` (singular is official).
    Credentials,
    /// POST `/reclaim/credential/<ego>`.
    CredentialStore,
    /// DELETE `/reclaim/credential/<ego>/<base32id>`.
    CredentialDelete,
    /// GET `/reclaim/tickets/<ego>`. There is no ticket-issue POST here.
    Tickets,
    /// POST `/reclaim/revoke` with gns_name.
    Revoke,
    /// POST `/reclaim/consume` with gns_name and rp_uri.
    Consume,
    /// GET `/copying`.
    Copying,
    /// GET `/config[/<section>]`.
    ConfigGet,
    /// POST `/config[/<section>]`, actual persistence before success.
    ConfigPost,
    /// GET `/gns/<name>` through an explicit existing query endpoint.
    GnsGet,
    /// Conditional GET/POST /openid/authorize.
    Authorize,
    /// Conditional POST /openid/login.
    Login,
    /// Conditional POST /openid/token.
    Token,
    /// Conditional GET/POST /openid/userinfo.
    Userinfo,
    /// Conditional GET /.well-known/openid-configuration.
    Discovery,
    /// Conditional GET /jwks.json.
    Jwks,
    /// Actual OPTIONS for the selected namespace.
    Options(Family),
}
/// One original decoded route and original raw query, with no private Debug data.
#[derive(Clone, Copy)]
pub struct Route<'a> {
    endpoint: Endpoint,
    suffix: &'a [u8],
    query: Query<'a>,
}
impl<'a> Route<'a> {
    /// Exact official endpoint, not a declaration of attached backend readiness.
    pub const fn endpoint(self) -> Endpoint {
        self.endpoint
    }
    /// Original decoded suffix after the selected namespace. Names may contain
    /// slash; NAMESTORE ego resolution must use the original actual directory.
    pub const fn suffix(self) -> &'a [u8] {
        self.suffix
    }
    /// Original raw query. Decode individual keys/values in caller scratch.
    pub const fn query(self) -> Query<'a> {
        self.query
    }
}
impl core::fmt::Debug for Route<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Route")
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}
/// Resolution is separate from native capability availability and HTTP response.
#[derive(Clone, Copy, Debug)]
pub enum Resolution<'a> {
    /// Recognized actual route with checked path/query framing.
    Found(Route<'a>),
    /// Unknown namespace/path; no private protocol route is manufactured.
    NotFound,
    /// Known namespace but unsupported method/path combination.
    MethodNotAllowed(Family),
}
/// Resolve a validated original HTTP request. Output path scratch must remain
/// alive with the returned route. Query stays borrowed from original input.
/// It strips one official trailing slash, validates percent escapes/UTF-8/NUL,
/// and requires a namespace boundary rather than accepting accidental C prefix
/// aliases such as /identityevil. No caller buffer is modified on capacity error.
pub fn resolve<'a>(request: &Request<'a>, path: &'a mut [u8]) -> Result<Resolution<'a>, Error> {
    resolve_parts(request.method(), request.target(), path)
}
/// Resolve the same checked method/target before a waiting client sends its
/// body. It grants no body validity or native backend admission.
pub fn resolve_head<'a>(
    head: &crate::http::RequestHead<'a>,
    path: &'a mut [u8],
) -> Result<Resolution<'a>, Error> {
    resolve_parts(head.method(), head.target(), path)
}
fn resolve_parts<'a>(
    method: &[u8],
    raw: &'a [u8],
    path: &'a mut [u8],
) -> Result<Resolution<'a>, Error> {
    let mark = raw.iter().position(|b| *b == b'?').unwrap_or(raw.len());
    let query = Query {
        raw: if mark < raw.len() {
            &raw[mark + 1..]
        } else {
            &[]
        },
    };
    let n = decode(&raw[..mark], path, false)?;
    let path = &path[..if n > 1 && path[n - 1] == b'/' {
        n - 1
    } else {
        n
    }];
    let is = |m: &[u8]| method.eq_ignore_ascii_case(m);
    let family = if within(path, b"/identity") || path == b"/sign" {
        Family::Identity
    } else if within(path, b"/namestore") {
        Family::Namestore
    } else if within(path, b"/reclaim") {
        Family::Reclaim
    } else if within(path, b"/copying") {
        Family::Copying
    } else if within(path, b"/config") {
        Family::Config
    } else if within(path, b"/gns") {
        Family::Gns
    } else if within(path, b"/openid")
        || path == b"/.well-known/openid-configuration"
        || path == b"/jwks.json"
    {
        Family::Openid
    } else {
        return Ok(Resolution::NotFound);
    };
    if is(b"OPTIONS") {
        return Ok(Resolution::Found(Route {
            endpoint: Endpoint::Options(family),
            suffix: &[],
            query,
        }));
    }
    let mut suffix = &[][..];
    let endpoint = match family {
        Family::Identity => {
            if path == b"/sign" && is(b"GET") {
                Some(Endpoint::IdentitySign)
            } else if path == b"/identity" {
                if is(b"GET") {
                    Some(Endpoint::Identities)
                } else if is(b"POST") {
                    Some(Endpoint::IdentityCreate)
                } else {
                    None
                }
            } else if let Some(name) = after(path, b"/identity/name") {
                suffix = name;
                if is(b"GET") {
                    Some(Endpoint::IdentityName)
                } else if is(b"PUT") {
                    Some(Endpoint::IdentityRenameName)
                } else if is(b"DELETE") {
                    Some(Endpoint::IdentityDeleteName)
                } else {
                    None
                }
            } else if let Some(key) = after(path, b"/identity/pubkey") {
                suffix = key;
                if is(b"GET") {
                    Some(Endpoint::IdentityPublic)
                } else if is(b"PUT") {
                    Some(Endpoint::IdentityRenamePublic)
                } else if is(b"DELETE") {
                    Some(Endpoint::IdentityDeletePublic)
                } else {
                    None
                }
            } else {
                None
            }
        }
        Family::Namestore => {
            if let Some(name) = after(path, b"/namestore/import") {
                suffix = name;
                if is(b"POST") {
                    Some(Endpoint::NameImport)
                } else {
                    None
                }
            } else if let Some(name) = after(path, b"/namestore") {
                suffix = name;
                if is(b"GET") {
                    Some(Endpoint::Names)
                } else if is(b"POST") {
                    Some(Endpoint::NameAppend)
                } else if is(b"PUT") {
                    Some(Endpoint::NameReplace)
                } else if is(b"DELETE") {
                    Some(Endpoint::NameDelete)
                } else {
                    None
                }
            } else {
                None
            }
        }
        Family::Reclaim => {
            if let Some(name) = after(path, b"/reclaim/attributes") {
                suffix = name;
                if is(b"GET") {
                    Some(Endpoint::Attributes)
                } else if is(b"POST") {
                    Some(Endpoint::AttributeStore)
                } else if is(b"DELETE") {
                    Some(Endpoint::AttributeDelete)
                } else {
                    None
                }
            } else if let Some(name) = after(path, b"/reclaim/credential") {
                suffix = name;
                if is(b"GET") {
                    Some(Endpoint::Credentials)
                } else if is(b"POST") {
                    Some(Endpoint::CredentialStore)
                } else if is(b"DELETE") {
                    Some(Endpoint::CredentialDelete)
                } else {
                    None
                }
            } else if let Some(name) = after(path, b"/reclaim/tickets") {
                suffix = name;
                if is(b"GET") {
                    Some(Endpoint::Tickets)
                } else {
                    None
                }
            } else if path == b"/reclaim/revoke" && is(b"POST") {
                Some(Endpoint::Revoke)
            } else if path == b"/reclaim/consume" && is(b"POST") {
                Some(Endpoint::Consume)
            } else {
                None
            }
        }
        Family::Copying => {
            if path == b"/copying" && is(b"GET") {
                Some(Endpoint::Copying)
            } else {
                None
            }
        }
        Family::Config => {
            suffix = after(path, b"/config").unwrap_or(&[]);
            if is(b"GET") {
                Some(Endpoint::ConfigGet)
            } else if is(b"POST") {
                Some(Endpoint::ConfigPost)
            } else {
                None
            }
        }
        Family::Gns => {
            suffix = after(path, b"/gns").unwrap_or(&[]);
            if is(b"GET") {
                Some(Endpoint::GnsGet)
            } else {
                None
            }
        }
        Family::Openid => {
            if path == b"/openid/authorize" && (is(b"GET") || is(b"POST")) {
                Some(Endpoint::Authorize)
            } else if path == b"/openid/login" && is(b"POST") {
                Some(Endpoint::Login)
            } else if path == b"/openid/token" && is(b"POST") {
                Some(Endpoint::Token)
            } else if path == b"/openid/userinfo" && (is(b"GET") || is(b"POST")) {
                Some(Endpoint::Userinfo)
            } else if path == b"/.well-known/openid-configuration" && is(b"GET") {
                Some(Endpoint::Discovery)
            } else if path == b"/jwks.json" && is(b"GET") {
                Some(Endpoint::Jwks)
            } else {
                None
            }
        }
    };
    Ok(match endpoint {
        Some(endpoint) => Resolution::Found(Route {
            endpoint,
            suffix,
            query,
        }),
        None => Resolution::MethodNotAllowed(family),
    })
}
fn within(path: &[u8], prefix: &[u8]) -> bool {
    path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|b| b.first() == Some(&b'/'))
}
fn after<'a>(path: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if path == prefix {
        Some(&[])
    } else {
        path.strip_prefix(prefix).and_then(|b| b.strip_prefix(b"/"))
    }
}
/// Original bounded raw query view; it neither logs values nor owns a cache.
#[derive(Clone, Copy)]
pub struct Query<'a> {
    raw: &'a [u8],
}
impl<'a> Query<'a> {
    /// Borrow a bounded original raw query without copying or interpreting it.
    pub const fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }
    /// Original encoded query bytes, for an explicitly owned request copy.
    pub const fn expose_raw(self) -> &'a [u8] {
        self.raw
    }

    /// Decode exact original bytes of one query value. Values may contain
    /// control/non-UTF8 bytes for raw `/sign` data; NUL is refused because the
    /// official consumer uses a C string. Keys remain strict UTF8 text.
    pub fn get_bytes(
        self,
        key: &[u8],
        key_scratch: &mut [u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let mut found = None;
        for part in self.raw.split(|b| *b == b'&').filter(|p| !p.is_empty()) {
            let equal = part.iter().position(|b| *b == b'=').unwrap_or(part.len());
            let n = decode(&part[..equal], key_scratch, true)?;
            if &key_scratch[..n] != key {
                continue;
            }
            if found.is_some() {
                return Err(Error::Conflict);
            }
            let input = if equal < part.len() {
                &part[equal + 1..]
            } else {
                &[]
            };
            found = Some(decode_octets(input, out, true)?);
        }
        Ok(found)
    }
    /// Decode one exact public key into caller output. Duplicate decoded keys
    /// are refused as Conflict rather than selecting an ambiguous authorization
    /// or mutation parameter. '+' maps to space ONLY in queries.
    pub fn get(
        self,
        key: &[u8],
        key_scratch: &mut [u8],
        value_out: &mut [u8],
    ) -> Result<Option<usize>, Error> {
        let mut found = None;
        for part in self.raw.split(|b| *b == b'&').filter(|p| !p.is_empty()) {
            let equal = part.iter().position(|b| *b == b'=').unwrap_or(part.len());
            let n = decode(&part[..equal], key_scratch, true)?;
            if &key_scratch[..n] != key {
                continue;
            }
            if found.is_some() {
                return Err(Error::Conflict);
            }
            found = Some(decode(
                if equal < part.len() {
                    &part[equal + 1..]
                } else {
                    &[]
                },
                value_out,
                true,
            )?);
        }
        Ok(found)
    }
}
impl core::fmt::Debug for Query<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Query([REDACTED])")
    }
}
/// URI percent decoding with explicit UTF-8/NUL validation and query-only plus.
/// Capacity refusal changes nothing. Syntax failure may write scratch, which
/// belongs to the original caller and must be erased if it contains private data.
pub fn decode(input: &[u8], out: &mut [u8], plus: bool) -> Result<usize, Error> {
    let mut n = 0usize;
    let mut at = 0;
    while at < input.len() {
        if input[at] == b'%' {
            hex(*input.get(at + 1).ok_or(Error::Malformed)?)?;
            hex(*input.get(at + 2).ok_or(Error::Malformed)?)?;
            at += 3;
        } else {
            at += 1;
        }
        n = n.checked_add(1).ok_or(Error::Overflow)?;
    }
    let out = out.get_mut(..n).ok_or(Error::Capacity)?;
    at = 0;
    let mut written = 0;
    while at < input.len() {
        let b = if input[at] == b'%' {
            let b = (hex(input[at + 1])? << 4) | hex(input[at + 2])?;
            at += 3;
            b
        } else {
            let b = input[at];
            at += 1;
            if plus && b == b'+' { b' ' } else { b }
        };
        if b == 0 || b < 0x20 || b == 0x7f {
            return Err(Error::Malformed);
        }
        out[written] = b;
        written += 1;
    }
    core::str::from_utf8(out).map_err(|_| Error::Malformed)?;
    Ok(n)
}
fn hex(b: u8) -> Result<u8, Error> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(Error::Malformed),
    }
}

fn decode_octets(input: &[u8], out: &mut [u8], plus: bool) -> Result<usize, Error> {
    let mut n = 0usize;
    let mut at = 0;
    while at < input.len() {
        if input[at] == b'%' {
            hex(*input.get(at + 1).ok_or(Error::Malformed)?)?;
            hex(*input.get(at + 2).ok_or(Error::Malformed)?)?;
            at += 3;
        } else {
            at += 1;
        }
        n = n.checked_add(1).ok_or(Error::Overflow)?;
    }
    let out = out.get_mut(..n).ok_or(Error::Capacity)?;
    at = 0;
    let mut written = 0;
    while at < input.len() {
        let b = if input[at] == b'%' {
            let b = (hex(input[at + 1])? << 4) | hex(input[at + 2])?;
            at += 3;
            b
        } else {
            let b = input[at];
            at += 1;
            if plus && b == b'+' { b' ' } else { b }
        };
        if b == 0 {
            return Err(Error::Malformed);
        }
        out[written] = b;
        written += 1;
    }
    Ok(n)
}
