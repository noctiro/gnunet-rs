use crate::{
    Context, Error, OwnedRequest, Response,
    output::{Json, bytes, decoded, parse, service},
};
use gnunet_reclaim::{
    Attribute, AttributeType, Credential, CredentialType, Identifier, Name, Sensitive, Ticket, Uri,
};
use gnunet_reclaim_client_host::{Client, Iterator, Outcome, Progress, Reply, ipc};
use gnunet_reclaim_credentials as formats;
use gnunet_rest::route::Endpoint;
use gnunet_types::Error as Fault;
use std::future::poll_fn;
use tokio::time::Instant;
use zeroize::Zeroizing;
impl<I: gnunet_dns::Idna> Context<'_, I> {
    pub(crate) async fn reclaim(
        &self,
        request: OwnedRequest,
        until: u64,
        hard: Instant,
    ) -> Result<Response, Error> {
        let path = match request.endpoint {
            Endpoint::Revoke | Endpoint::Consume => None,
            _ => Some(subject_path(request.endpoint, &request.suffix)?),
        };
        let mut client = Client::new(
            self.instances.reclaim,
            self.sources.reclaim.duplicate()?,
            self.limits.reclaim,
        )?;
        if matches!(request.endpoint, Endpoint::Revoke | Endpoint::Consume) {
            let (name, uri) = parse(&request.body, self.limits.json, |root| {
                let spec = gnunet_rest::contracts::Ticket::parse(
                    root,
                    request.endpoint == Endpoint::Consume,
                )?;
                Ok((decoded(spec.name)?, spec.uri.map(decoded).transpose()?))
            })?;
            let ticket = Ticket::new(&name)?;
            let issuer = ticket.capability()?.1;
            let operation = if request.endpoint == Endpoint::Consume {
                client.consume_ticket(
                    ticket,
                    Uri::new(uri.as_deref().ok_or(Fault::InvalidInput)?)?,
                    until,
                )?
            } else {
                let directory = self.directory(hard).await?;
                let mut key = None;
                for ego in directory.egos() {
                    if ego.public_key()? == issuer.to_wire() {
                        key = Some(ego.secret().try_clone_secret());
                        break;
                    }
                }
                let key = key.ok_or_else(|| service(200))?;
                client.revoke_ticket(key.view()?, ticket, until)?
            };
            let reply = reclaim_reply(&mut client, operation, hard).await?;
            return match reply.view()? {
                ipc::Response::Revoked { result: 1, .. } => Ok(Response::empty(200)),
                ipc::Response::Revoked { result, .. } => Err(Error::Status(i64::from(result))),
                ipc::Response::Consumed {
                    result,
                    identity,
                    attributes,
                    ..
                } => {
                    self.consume_profile.validate(result, identity, issuer)?;
                    let response = (|| -> Result<Response, Error> {
                        let mut json = Json::new(self.limits.output_bytes)?;
                        json.raw(b"{")?;
                        for (n, item) in attributes.iter().enumerate() {
                            if n >= self.limits.items {
                                return Err(Fault::Capacity.into());
                            }
                            if n != 0 {
                                json.raw(b",")?
                            }
                            json.string(item.name.bytes())?;
                            json.raw(b":")?;
                            json.string(
                                formats::attribute_value_string(item.kind, item.value)?.expose(),
                            )?;
                        }
                        json.raw(b"}")?;
                        let mut response = Response::json(json.bytes);
                        response.service_status = Some(i64::from(result));
                        Ok(response)
                    })();
                    response.map_err(|original| Error::ConsumeReply {
                        raw: result,
                        original: Box::new(original),
                    })
                }
                _ => Err(Fault::Malformed.into()),
            };
        }
        let (name, tail) = path.ok_or(Fault::InvalidInput)?;
        let directory = self.directory(hard).await?;
        let key = match directory.egos().find(|ego| ego.name() == name) {
            Some(ego) => ego.secret().try_clone_secret(),
            None if matches!(
                request.endpoint,
                Endpoint::Attributes
                    | Endpoint::Credentials
                    | Endpoint::Tickets
                    | Endpoint::AttributeDelete
                    | Endpoint::CredentialDelete
            ) =>
            {
                return Ok(Response::json(crate::output::copy(b"[]")?));
            }
            None => return Err(service(200)),
        };
        if matches!(
            request.endpoint,
            Endpoint::Attributes | Endpoint::Credentials | Endpoint::Tickets
        ) {
            let kind = match request.endpoint {
                Endpoint::Attributes => ipc::Iteration::Attributes,
                Endpoint::Credentials => ipc::Iteration::Credentials,
                _ => ipc::Iteration::Tickets,
            };
            let mut iterator = Iterator::new(
                self.instances.reclaim,
                self.sources.reclaim.duplicate()?,
                key.view()?,
                kind,
                until,
                self.limits.reclaim,
            )?;
            let mut json = Json::new(self.limits.output_bytes)?;
            json.raw(b"[")?;
            let mut count = 0;
            loop {
                match poll_fn(|cx| iterator.poll(cx, Some(hard))).await? {
                    Progress::Item { reply, .. } => {
                        if count >= self.limits.items {
                            return Err(Fault::Capacity.into());
                        }
                        if count != 0 {
                            json.raw(b",")?
                        }
                        match reply.view()? {
                            ipc::Response::Attribute {
                                attribute: Some(item),
                                ..
                            } => attribute_json(&mut json, item, false)?,
                            ipc::Response::Credential {
                                credential: Some(item),
                                ..
                            } => self.credential_json(&mut json, item)?,
                            ipc::Response::Ticket {
                                ticket: Some(ticket),
                                uri: Some(uri),
                                ..
                            } => {
                                json.raw(b"{\"gns_name\":")?;
                                json.string(ticket.expose())?;
                                json.raw(b",\"rp_uri\":")?;
                                json.string(uri.expose())?;
                                json.raw(b"}")?;
                            }
                            _ => return Err(Fault::Malformed.into()),
                        }
                        count += 1;
                        if kind != ipc::Iteration::Tickets {
                            iterator.next(until)?;
                        }
                    }
                    Progress::Completed(c) => {
                        if let Outcome::Local { reason, submission } = c.outcome {
                            return Err(Error::ReclaimRetired { reason, submission });
                        }
                        json.raw(b"]")?;
                        return Ok(Response::json(json.bytes));
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
        let operation = match request.endpoint {
            Endpoint::AttributeStore => parse(&request.body, self.limits.json, |root| {
                let spec = gnunet_rest::contracts::Attribute::parse(root)?;
                let name = normalize(&decoded(spec.name)?, self.limits.bytes)?;
                let kind =
                    formats::attribute_type(&decoded(spec.kind)?).ok_or(Fault::Unsupported)?;
                let mut value = bytes(self.limits.bytes)?;
                let n = formats::attribute_from_string(kind, &decoded(spec.value)?, &mut value)?;
                let item = Attribute::new(
                    identifier(spec.id)?,
                    identifier(spec.credential)?,
                    kind,
                    Name::new(&name)?,
                    Sensitive::new(&value[..n]),
                );
                Ok(client.store_attribute(
                    key.view()?,
                    item,
                    gnunet_wire::official::RelativeTime::from_micros(3_600_000_000),
                    until,
                )?)
            })?,
            Endpoint::CredentialStore => parse(&request.body, self.limits.json, |root| {
                let spec = gnunet_rest::contracts::Credential::parse(root)?;
                let name = normalize(&decoded(spec.name)?, self.limits.bytes)?;
                let kind =
                    formats::credential_type(&decoded(spec.kind)?).ok_or(Fault::Unsupported)?;
                if kind != CredentialType::JWT {
                    return Err(Fault::Unsupported.into());
                }
                let text = if spec.value.kind() == gnunet_json::ValueKind::String {
                    decoded(spec.value.string()?)?
                } else {
                    compact(spec.value.expose_json(), self.limits.bytes)?
                };
                let mut value = bytes(self.limits.bytes)?;
                let n = formats::credential_from_string(kind, &text, &mut value)?;
                let item = Credential::new(
                    identifier(spec.id)?,
                    kind,
                    Name::new(&name)?,
                    Sensitive::new(&value[..n]),
                );
                Ok(client.store_credential(
                    key.view()?,
                    item,
                    gnunet_wire::official::RelativeTime::from_micros(3_600_000_000),
                    until,
                )?)
            })?,
            Endpoint::AttributeDelete | Endpoint::CredentialDelete => {
                let mut id = [0u8; 32];
                gnunet_rest::text::decode(tail, &mut id)?;
                let id = Identifier::new(id);
                if request.endpoint == Endpoint::AttributeDelete {
                    client.delete_attribute(
                        key.view()?,
                        Attribute::new(
                            id,
                            Identifier::ZERO,
                            AttributeType::NONE,
                            Name::new(&[])?,
                            Sensitive::new(&[]),
                        ),
                        until,
                    )?
                } else {
                    client.delete_credential(
                        key.view()?,
                        Credential::new(
                            id,
                            CredentialType::NONE,
                            Name::new(&[])?,
                            Sensitive::new(&[]),
                        ),
                        until,
                    )?
                }
            }
            _ => return Err(Fault::InvalidInput.into()),
        };
        let reply = reclaim_reply(&mut client, operation, hard).await?;
        match reply.view()? {
            ipc::Response::Success { result: 1, .. } => Ok(Response::empty(200)),
            ipc::Response::Success { result, .. } => Err(Error::Status(i64::from(result))),
            _ => Err(Fault::Malformed.into()),
        }
    }
    fn credential_json(&self, json: &mut Json, item: Credential<'_>) -> Result<(), Error> {
        json.raw(b"{\"value\":")?;
        json.string(formats::credential_value_string(item.kind, item.value)?.expose())?;
        json.raw(b",\"name\":")?;
        json.string(item.name.bytes())?;
        json.raw(b",\"type\":")?;
        json.string(if item.kind == CredentialType::JWT {
            b"JWT"
        } else if item.kind == CredentialType::PABC {
            b"PABC"
        } else {
            return Err(Fault::Unsupported.into());
        })?;
        json.raw(b",\"id\":")?;
        json.base32(item.id.bytes())?;
        let mut payload = bytes(self.limits.bytes)?;
        let mut tokens = Vec::new();
        tokens
            .try_reserve_exact(self.limits.json.nodes)
            .map_err(|_| Fault::Capacity)?;
        tokens.resize(self.limits.json.nodes, gnunet_json::Token::EMPTY);
        let mut stack = Vec::new();
        stack
            .try_reserve_exact(self.limits.json.depth)
            .map_err(|_| Fault::Capacity)?;
        stack.resize(self.limits.json.depth, gnunet_json::Nest::EMPTY);
        let mut workspace = formats::Workspace::new(&mut payload, &mut tokens, &mut stack);
        let limits = formats::Limits {
            input_bytes: self.limits.bytes,
            payload_bytes: self.limits.bytes,
            nodes: self.limits.json.nodes,
            depth: self.limits.json.depth,
            attributes: self.limits.items,
            work: self.limits.json.work,
        };
        let claims = workspace.credential(item, limits)?;
        if let Some(issuer) = claims.lookup(b"iss") {
            let issuer = issuer.string()?;
            json.raw(b",\"issuer\":")?;
            json.string(&decoded(issuer)?)?;
        }
        if claims.lookup(b"exp").is_some() {
            json.raw(b",\"expiration\":")?;
            json.number(claims.expiration()?.as_micros())?;
        }
        json.raw(b",\"attributes\":[")?;
        for (n, claim) in claims.attributes().enumerate() {
            if n >= self.limits.items {
                return Err(Fault::Capacity.into());
            }
            if n != 0 {
                json.raw(b",")?
            }
            let name = normalize(&decoded(claim.name)?, self.limits.bytes)?;
            let mut value = bytes(claim.value.attribute_len()?)?;
            claim.value.write_attribute(&mut value)?;
            let item = Attribute::new(
                Identifier::ZERO,
                Identifier::ZERO,
                AttributeType::STRING,
                Name::new(&name)?,
                Sensitive::new(&value),
            );
            attribute_json(json, item, true)?;
        }
        json.raw(b"]}")?;
        Ok(())
    }
}
fn subject_path(endpoint: Endpoint, suffix: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    match endpoint {
        Endpoint::AttributeDelete | Endpoint::CredentialDelete => {
            let mut tokens = suffix.split(|byte| *byte == b'/').filter(|p| !p.is_empty());
            let name = tokens.next().ok_or(Fault::InvalidInput)?;
            let id = tokens.next().ok_or(Fault::InvalidInput)?;
            Ok((name, id))
        }
        Endpoint::Attributes
        | Endpoint::AttributeStore
        | Endpoint::Credentials
        | Endpoint::CredentialStore
        | Endpoint::Tickets
            if !suffix.is_empty() =>
        {
            Ok((suffix, &[]))
        }
        _ => Err(Fault::InvalidInput.into()),
    }
}
fn attribute_json(json: &mut Json, item: Attribute<'_>, derived: bool) -> Result<(), Error> {
    json.raw(b"{\"value\":")?;
    json.string(formats::attribute_value_string(item.kind, item.value)?.expose())?;
    json.raw(b",\"name\":")?;
    json.string(item.name.bytes())?;
    json.raw(b",\"flag\":")?;
    json.string(if derived || !item.credential.is_zero() {
        b"1"
    } else {
        b"0"
    })?;
    json.raw(b",\"type\":\"STRING\",\"id\":")?;
    if derived {
        json.string(b"")?
    } else {
        json.base32(item.id.bytes())?
    }
    json.raw(b",\"credential\":")?;
    if derived {
        json.string(b"")?
    } else {
        json.base32(item.credential.bytes())?
    }
    json.raw(b"}")
}
fn identifier(s: Option<gnunet_json::JsonString<'_>>) -> Result<Identifier, Error> {
    let Some(s) = s else {
        return Ok(Identifier::ZERO);
    };
    let text = decoded(s)?;
    if text.is_empty() {
        return Ok(Identifier::ZERO);
    }
    let mut raw = [0u8; 32];
    gnunet_rest::text::decode(&text, &mut raw)?;
    Ok(Identifier::new(raw))
}
fn normalize(input: &[u8], cap: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = bytes(cap)?;
    let make = || -> Result<Zeroizing<Vec<u32>>, Error> {
        let mut v = Vec::new();
        v.try_reserve_exact(cap).map_err(|_| Fault::Capacity)?;
        v.resize(cap, 0);
        Ok(Zeroizing::new(v))
    };
    let mut lower = make()?;
    let mut nfd = make()?;
    let mut order = make()?;
    let n =
        gnunet_identity::normalize_name_into(input, &mut out, &mut lower, &mut nfd, &mut order)?;
    out.truncate(n);
    Ok(out)
}
fn compact(input: &[u8], cap: usize) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = Json::new(cap)?;
    let mut string = false;
    let mut escaped = false;
    for b in input {
        if string {
            out.raw(&[*b])?;
            if escaped {
                escaped = false
            } else if *b == b'\\' {
                escaped = true
            } else if *b == b'"' {
                string = false
            }
        } else if *b == b'"' {
            string = true;
            out.raw(&[*b])?
        } else if !b.is_ascii_whitespace() {
            out.raw(&[*b])?;
        }
    }
    Ok(out.bytes)
}
pub(crate) async fn reclaim_reply<'id>(
    client: &mut Client<'id>,
    operation: gnunet_reclaim_client_host::Operation<'id>,
    hard: Instant,
) -> Result<Reply, Error> {
    loop {
        match poll_fn(|cx| client.poll(cx, Some(hard))).await? {
            Progress::Completed(c) if c.operation == operation => {
                return match c.outcome {
                    Outcome::Reply(reply) => Ok(reply),
                    Outcome::Local { reason, submission } => {
                        Err(Error::ReclaimRetired { reason, submission })
                    }
                };
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
