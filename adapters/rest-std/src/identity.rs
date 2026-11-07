use crate::{
    Context, Error, OwnedRequest, Response,
    output::{Json, decoded, parse, service},
};
use gnunet_identity_client_host::{Client, KeyType, Outcome, Progress, SecretKey};
use gnunet_rest::route::Endpoint;
use gnunet_types::Error as Fault;
use std::future::poll_fn;
use tokio::time::Instant;
use zeroize::Zeroizing;
struct Entropy;
impl gnunet_crypto::Entropy for Entropy {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Fault> {
        getrandom::fill(out).map_err(|_| Fault::NotReady)
    }
}
impl<I: gnunet_dns::Idna> Context<'_, I> {
    pub(crate) async fn identity(
        &self,
        request: OwnedRequest,
        until: u64,
        hard: Instant,
    ) -> Result<Response, Error> {
        use Endpoint::*;
        if request.endpoint == IdentityCreate {
            // Only the bounded JSON/field phase has C's IDENTITY_INVALID
            // classification. Allocation/resource faults retain their original
            // cause; no key decoding, entropy or native operation is inside it.
            let (name, kind, private) = parse(&request.body, self.limits.json, |root| {
                let spec = gnunet_rest::contracts::IdentityCreate::parse(root)?;
                let name = decoded(spec.name)?;
                let private = spec.private.map(decoded).transpose()?;
                Ok((name, spec.kind, private))
            })
            .map_err(identity_input)?;
            let key = if let Some(text) = private {
                // The existing decoded text owner is already zeroizing. Move
                // it directly; no ordinary private Vec/String copy is made.
                let mut raw = Zeroizing::new([0u8; 36]);
                gnunet_rest::text::decode(&text, &mut *raw)?;
                SecretKey::new(*raw)?
            } else {
                SecretKey::generate(kind, &mut Entropy)?
            };
            let mut client = Client::new(
                self.instances.identity,
                self.sources.identity.duplicate()?,
                self.limits.identity,
            )?;
            let operation = client.create(&name, key, until)?;
            return id_result(&mut client, operation, hard, 201).await;
        }
        let directory = self.directory(hard).await?;
        if request.endpoint == Identities {
            let private = request.query(b"private", self.limits.bytes)?.is_some();
            let mut json = Json::new(self.limits.output_bytes)?;
            json.raw(b"[")?;
            for (n, ego) in directory.egos().enumerate() {
                if n >= self.limits.items {
                    return Err(Fault::Capacity.into());
                }
                if n != 0 {
                    json.raw(b",")?
                }
                ego_json(&mut json, &ego, private)?;
            }
            json.raw(b"]")?;
            return Ok(Response::json(json.bytes));
        }
        if request.endpoint == IdentitySign {
            let user = request
                .query(b"user", self.limits.bytes)?
                .ok_or(Fault::InvalidInput)?;
            let data = request
                .query_bytes(b"data", self.limits.bytes)?
                .ok_or(Fault::InvalidInput)?;
            let ego = directory
                .egos()
                .find(|e| e.name() == user.as_slice())
                .ok_or_else(|| service(200))?;
            if ego.secret().view()?.key_type() != KeyType::Eddsa {
                return Err(Fault::Unsupported.into());
            }
            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&ego.secret().expose_serialized()[4..]);
            let key = gnunet_crypto::EddsaPrivateKey::from_seed(*seed);
            let signature = key.sign_raw(&data);
            let mut encoded = [0u8; 86];
            base64url(signature.as_bytes(), &mut encoded)?;
            let mut json = Json::new(self.limits.output_bytes)?;
            json.raw(b"{\"signature\":")?;
            json.string(&encoded)?;
            json.raw(b"}")?;
            return Ok(Response::json(json.bytes));
        }
        let public = matches!(
            request.endpoint,
            IdentityPublic | IdentityRenamePublic | IdentityDeletePublic
        );
        let mut selected = None;
        if public {
            let mut raw = [0u8; 36];
            gnunet_rest::text::decode(&request.suffix, &mut raw)?;
            gnunet_gnsrecord::ZoneKey::from_wire(&raw)?;
            for ego in directory.egos() {
                if ego.public_key()? == raw {
                    selected = Some(ego);
                    break;
                }
            }
        } else {
            selected = directory
                .egos()
                .find(|e| e.name().eq_ignore_ascii_case(request.suffix.as_slice()));
        }
        let ego = selected.ok_or_else(|| service(200))?;
        if matches!(request.endpoint, IdentityName | IdentityPublic) {
            let mut json = Json::new(self.limits.output_bytes)?;
            ego_json(
                &mut json,
                &ego,
                request.query(b"private", self.limits.bytes)?.is_some(),
            )?;
            return Ok(Response::json(json.bytes));
        }
        let mut client = Client::new(
            self.instances.identity,
            self.sources.identity.duplicate()?,
            self.limits.identity,
        )?;
        let operation = if matches!(request.endpoint, IdentityRenameName | IdentityRenamePublic) {
            let name = parse(&request.body, self.limits.json, |root| {
                decoded(gnunet_rest::contracts::identity_rename(root)?)
            })
            .map_err(identity_input)?;
            client.rename(ego.name(), &name, until)?
        } else {
            client.delete(ego.name(), until)?
        };
        id_result(&mut client, operation, hard, 204).await
    }
}
// Fixed identity_plugin.c rejects empty bodies, invalid JSON and invalid
// create/rename field shapes as GNUNET_EC_IDENTITY_INVALID (202). This helper
// is used only on those local body phases. In particular, a buffer/allocator,
// clock, entropy, imported-key codec or native failure is never recategorized.
fn identity_input(error: Error) -> Error {
    match error {
        Error::Core(Fault::InvalidInput | Fault::Malformed | Fault::Truncated) => service(202),
        original => original,
    }
}
fn ego_json(
    json: &mut Json,
    ego: &gnunet_identity_client_host::EgoView<'_, '_>,
    private: bool,
) -> Result<(), Error> {
    json.raw(b"{\"pubkey\":")?;
    json.base32(&ego.public_key()?)?;
    json.raw(b",\"name\":")?;
    json.string(ego.name())?;
    if private {
        json.raw(b",\"privkey\":")?;
        json.base32(ego.secret().expose_serialized())?;
    }
    json.raw(b"}")
}
async fn id_result<'id>(
    client: &mut Client<'id>,
    operation: gnunet_identity_client_host::Operation<'id>,
    hard: Instant,
    status: u16,
) -> Result<Response, Error> {
    loop {
        match poll_fn(|cx| client.poll(cx, Some(hard))).await? {
            Progress::Completed(c) if c.operation == operation => {
                let result = match c.outcome {
                    Outcome::Result { code: 0, .. } => Ok(Response::empty(status)),
                    Outcome::Result { code, .. } => Err(service(code)),
                    Outcome::Local {
                        reason,
                        submission,
                        result_code,
                        ..
                    } => Err(Error::IdentityRetired {
                        reason,
                        submission,
                        result_code,
                    }),
                    _ => Err(Error::Retired),
                };
                let _original_loss = client.close();
                return result;
            }
            Progress::Lost { cause, .. } => return Err(Error::IdentitySource(cause)),
            Progress::Unavailable(error) => return Err(Error::Native(error)),
            Progress::ConnectRetry { error, .. } => return Err(Error::Io(error)),
            Progress::Closed => return Err(Error::SourceLost),
            Progress::WaitDeadline => return Err(Error::Deadline),
            _ => {}
        }
    }
}
fn base64url(input: &[u8; 64], out: &mut [u8; 86]) -> Result<(), Error> {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut bits = 0u32;
    let mut count = 0;
    let mut at = 0;
    for b in input {
        bits = (bits << 8) | u32::from(*b);
        count += 8;
        while count >= 6 {
            count -= 6;
            out[at] = A[((bits >> count) & 63) as usize];
            at += 1;
        }
    }
    if count != 0 {
        out[at] = A[((bits << (6 - count)) & 63) as usize];
        at += 1;
    }
    if at != out.len() {
        return Err(Fault::Malformed.into());
    }
    Ok(())
}
