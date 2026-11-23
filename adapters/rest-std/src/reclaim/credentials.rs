//! Original credential rows with optional JWT metadata for RECLAIM GET.
use super::{attribute_json, normalize};
use crate::{
    Error, Limits,
    output::{Json, bytes, decoded},
};
use gnunet_reclaim::{
    Attribute, AttributeType, Credential, CredentialType, Identifier, Name, Sensitive,
};
use gnunet_reclaim_credentials as formats;
use gnunet_types::Error as Fault;
use zeroize::Zeroizing;

pub(super) struct CredentialRows {
    limits: formats::Limits,
    scratch: Option<Scratch>,
}

impl CredentialRows {
    pub(super) fn new(limits: Limits) -> Self {
        Self {
            limits: formats::Limits {
                input_bytes: limits.bytes,
                payload_bytes: limits.bytes,
                nodes: limits.json.nodes,
                depth: limits.json.depth,
                attributes: limits.items,
                work: limits.json.work,
            },
            scratch: None,
        }
    }

    pub(super) fn write(&mut self, json: &mut Json, item: Credential<'_>) -> Result<(), Error> {
        let kind = formats::credential_type_name(item.kind);
        json.raw(b"{")?;
        if kind.is_some() {
            json.raw(b"\"value\":")?;
            json.string(formats::credential_value_string(item.kind, item.value)?.expose())?;
            json.raw(b",")?;
        }
        json.raw(b"\"name\":")?;
        json.string(item.name.bytes())?;
        if let Some(kind) = kind {
            json.raw(b",\"type\":")?;
            json.string(kind.as_bytes())?;
        }
        json.raw(b",\"id\":")?;
        json.base32(item.id.bytes())?;
        if item.kind == CredentialType::JWT {
            self.write_claims(json, item)?;
        }
        json.raw(b"}")
    }

    fn write_claims(&mut self, json: &mut Json, item: Credential<'_>) -> Result<(), Error> {
        let scratch = match &mut self.scratch {
            Some(scratch) => scratch,
            slot => slot.insert(Scratch::new(self.limits)?),
        };
        let mut workspace = formats::Workspace::new(
            &mut scratch.payload,
            &mut scratch.tokens,
            &mut scratch.stack,
        );
        // A credential can be stored as text without a valid JWT payload. The
        // list still owns its original row and only enriches it with usable claims.
        let claims = match workspace.credential(item, self.limits) {
            Ok(claims) => claims,
            Err(error)
                if matches!(error.cause, Fault::Malformed | Fault::Conflict)
                    // An out-of-range JSON number belongs to the stored JWT payload.
                    || (error.stage == formats::Stage::Json && error.cause == Fault::Overflow) =>
            {
                return json.raw(b",\"attributes\":[]");
            }
            Err(error) => return Err(error.into()),
        };

        if let Ok(issuer) = claims.issuer() {
            json.raw(b",\"issuer\":")?;
            json.string(&decoded(issuer)?)?;
        }
        if let Ok(expiration) = claims.expiration() {
            json.raw(b",\"expiration\":")?;
            json.number(expiration.as_micros())?;
        }
        json.raw(b",\"attributes\":[")?;
        for (index, claim) in claims.attributes().enumerate() {
            if index != 0 {
                json.raw(b",")?;
            }
            let name = normalize(&decoded(claim.name)?, self.limits.input_bytes)?;
            let mut value = bytes(claim.value.attribute_len()?)?;
            claim.value.write_attribute(&mut value)?;
            let attribute = Attribute::new(
                Identifier::ZERO,
                Identifier::ZERO,
                AttributeType::STRING,
                Name::new(&name)?,
                Sensitive::new(&value),
            );
            attribute_json(json, attribute, true)?;
        }
        json.raw(b"]")
    }
}

struct Scratch {
    payload: Zeroizing<Vec<u8>>,
    tokens: Vec<gnunet_json::Token>,
    stack: Vec<gnunet_json::Nest>,
}

impl Scratch {
    fn new(limits: formats::Limits) -> Result<Self, Error> {
        let mut tokens = Vec::new();
        tokens
            .try_reserve_exact(limits.nodes)
            .map_err(|_| Fault::Capacity)?;
        tokens.resize(limits.nodes, gnunet_json::Token::EMPTY);
        let mut stack = Vec::new();
        stack
            .try_reserve_exact(limits.depth)
            .map_err(|_| Fault::Capacity)?;
        stack.resize(limits.depth, gnunet_json::Nest::EMPTY);
        Ok(Self {
            payload: bytes(limits.payload_bytes)?,
            tokens,
            stack,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::parse;

    fn item(kind: CredentialType, value: &[u8]) -> Result<Credential<'_>, Error> {
        Ok(Credential::new(
            Identifier::new([0x19; 32]),
            kind,
            Name::new(b"example")?,
            Sensitive::new(value),
        ))
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The assertions check the original stored rows and their independently derived JSON fields"
    )]
    fn opaque_rows_and_invalid_jwt_fields_do_not_hide_other_credentials() -> Result<(), Error> {
        let limits = Limits::default();
        let mut output = Json::new(limits.output_bytes)?;
        let mut credentials = CredentialRows::new(limits);
        output.raw(b"[")?;
        for (index, credential) in [
            item(CredentialType::JWT, b"header.e25vIEpTT04.signature")?,
            item(
                CredentialType::JWT,
                b"header.eyJleHAiOjE4NDQ2NzQ0MDczNzA5NTUxNjE2fQ.signature",
            )?,
            item(CredentialType::PABC, b"opaque-pabc")?,
            item(CredentialType::new(42), b"unregistered")?,
            item(
                CredentialType::JWT,
                b"header.eyJpc3MiOjcsImV4cCI6ImJhZCIsIkVtYWlsIjoibWFpbEBleGFtcGxlLnRlc3QifQ.signature",
            )?,
            item(
                CredentialType::JWT,
                b"header.eyJpc3MiOiJpc3N1ZXIiLCJleHAiOjJ9.signature",
            )?,
        ]
        .into_iter()
        .enumerate()
        {
            if index != 0 {
                output.raw(b",")?;
            }
            credentials.write(&mut output, credential)?;
        }
        output.raw(b"]")?;

        parse(&output.bytes, limits.json, |root| {
            let mut rows = root.elements()?;
            for _ in 0..2 {
                let invalid = rows.next().ok_or(Fault::NotFound)?;
                assert!(
                    invalid
                        .get(b"attributes")
                        .ok_or(Fault::NotFound)?
                        .elements()?
                        .next()
                        .is_none()
                );
            }
            let opaque = rows.next().ok_or(Fault::NotFound)?;
            assert!(
                opaque
                    .get(b"value")
                    .ok_or(Fault::NotFound)?
                    .string()?
                    .eq_ascii(b"opaque-pabc")
            );
            assert!(
                opaque
                    .get(b"type")
                    .ok_or(Fault::NotFound)?
                    .string()?
                    .eq_ascii(b"PABC")
            );
            assert!(opaque.get(b"attributes").is_none());
            let unknown = rows.next().ok_or(Fault::NotFound)?;
            assert!(unknown.get(b"id").is_some());
            assert!(unknown.get(b"type").is_none() && unknown.get(b"value").is_none());
            let incomplete = rows.next().ok_or(Fault::NotFound)?;
            assert!(incomplete.get(b"issuer").is_none() && incomplete.get(b"expiration").is_none());
            let email = incomplete
                .get(b"attributes")
                .ok_or(Fault::NotFound)?
                .elements()?
                .next()
                .ok_or(Fault::NotFound)?;
            assert!(
                email
                    .get(b"name")
                    .ok_or(Fault::NotFound)?
                    .string()?
                    .eq_ascii(b"email")
            );
            let valid = rows.next().ok_or(Fault::NotFound)?;
            assert!(
                valid
                    .get(b"issuer")
                    .ok_or(Fault::NotFound)?
                    .string()?
                    .eq_ascii(b"issuer")
            );
            assert_eq!(
                valid.get(b"expiration").ok_or(Fault::NotFound)?.integer()?,
                2_000_000
            );
            assert!(rows.next().is_none());
            Ok(())
        })
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "The assertions distinguish real resource and JSON output failures from unavailable metadata"
    )]
    fn resource_and_encoding_failures_remain_errors() -> Result<(), Error> {
        let mut limits = Limits::default();
        limits.json.nodes = 1;
        let mut credentials = CredentialRows::new(limits);
        let valid = item(CredentialType::JWT, b"header.eyJleHAiOjJ9.signature")?;
        assert!(matches!(
            credentials.write(&mut Json::new(limits.output_bytes)?, valid),
            Err(Error::Credential(formats::Failure {
                cause: Fault::Capacity,
                ..
            }))
        ));
        assert!(matches!(
            credentials.write(&mut Json::new(1)?, valid),
            Err(Error::Core(Fault::Capacity))
        ));
        assert!(matches!(
            credentials.write(
                &mut Json::new(limits.output_bytes)?,
                item(CredentialType::PABC, b"\xff")?,
            ),
            Err(Error::Core(Fault::Malformed))
        ));
        Ok(())
    }
}
