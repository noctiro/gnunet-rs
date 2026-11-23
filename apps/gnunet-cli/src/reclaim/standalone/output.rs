//! Official text output from typed, offset-checked RECLAIM replies.
use super::super::{
    Attribute, Credential, Identifier, Output, Presentation, Result, Sensitive, credentials, ipc,
};
use std::io::Write;
use zeroize::Zeroizing;

pub(in crate::reclaim) fn reply<W: Write>(
    out: &mut Output<'_, W>,
    response: ipc::Response<'_>,
) -> Result<bool> {
    match response {
        ipc::Response::Success { result: 1, .. } | ipc::Response::Revoked { result: 1, .. } => {}
        ipc::Response::Success { result, .. } => {
            return Err(format!("RECLAIM service rejected the operation ({result})").into());
        }
        ipc::Response::Revoked { result, .. } => {
            return Err(format!("Revocation failed ({result}).").into());
        }
        ipc::Response::Attribute {
            attribute: Some(attribute),
            ..
        } => attribute_row(out, attribute)?,
        ipc::Response::Credential {
            credential: Some(credential),
            ..
        } => credential_row(out, credential)?,
        ipc::Response::Ticket {
            ticket: Some(ticket),
            uri,
            ..
        } => {
            if let Some(uri) = uri {
                out.line(&[b"Ticket: ", ticket.expose(), b" | RP URI: ", uri.expose()])?;
            } else {
                out.line(&[ticket.expose()])?;
            }
        }
        ipc::Response::Consumed {
            result,
            identity,
            attributes,
            presentations,
            ..
        } => {
            if result != 1 || identity.is_none() {
                return Err(format!("Ticket consumption returned status {result} without a successful identity result").into());
            }
            let mut scratch = None;
            for attribute in attributes.iter() {
                let presentation = if attribute.credential.is_zero() {
                    None
                } else {
                    presentations
                        .iter()
                        .find(|item| item.credential == attribute.credential)
                };
                consumed_row(out, attribute, presentation, &mut scratch)?;
            }
        }
        _ => return Err("RECLAIM service returned no requested item".into()),
    }
    Ok(true)
}

fn encoded_id(id: Identifier) -> Result<[u8; 52]> {
    let mut encoded = [0; 52];
    gnunet::gnsrecord::encode_base32(id.bytes(), &mut encoded)?;
    Ok(encoded)
}

fn attribute_value(attribute: Attribute<'_>) -> &[u8] {
    credentials::attribute_value_string(attribute.kind, attribute.value)
        .map_or(b"???".as_slice(), Sensitive::expose)
}

fn attribute_row<W: Write>(out: &mut Output<'_, W>, attribute: Attribute<'_>) -> Result<()> {
    let id = encoded_id(attribute.id)?;
    let kind = credentials::attribute_type_name(attribute.kind)
        .unwrap_or("???")
        .as_bytes();
    let value = attribute_value(attribute);
    if attribute.credential.is_zero() {
        out.line(&[
            attribute.name.bytes(),
            b": ``",
            value,
            b"'' (",
            kind,
            b"); ID: ",
            &id,
        ])
    } else {
        let credential = encoded_id(attribute.credential)?;
        out.line(&[
            attribute.name.bytes(),
            b": ``",
            value,
            b"'' in credential presentation `",
            &credential,
            b"' (",
            kind,
            b"); ID: ",
            &id,
        ])
    }
}

fn credential_row<W: Write>(out: &mut Output<'_, W>, credential: Credential<'_>) -> Result<()> {
    let id = encoded_id(credential.id)?;
    let kind = credentials::credential_type_name(credential.kind)
        .unwrap_or("???")
        .as_bytes();
    let value = credentials::credential_value_string(credential.kind, credential.value)
        .map_or(b"???".as_slice(), Sensitive::expose);
    out.line(&[
        credential.name.bytes(),
        b": ``",
        value,
        b"'' (",
        kind,
        b"); ID: ",
        &id,
    ])?;
    if credential.kind != super::super::CredentialType::JWT {
        return Ok(());
    }
    let mut scratch = ClaimScratch::new();
    let (mut workspace, limits) = scratch.workspace();
    if let Ok(claims) = workspace.credential(credential, limits) {
        out.line(&[b"\t Attributes:"])?;
        for claim in claims.attributes() {
            let mut name = Zeroizing::new(vec![0; claim.name.decoded_len()?]);
            claim.name.decode(&mut name)?;
            let value = claim_value(claim.value)?;
            out.line(&[b"\t ", &name, b": ", &value])?;
        }
    }
    Ok(())
}

fn claim_value(claim: credentials::JsonValue<'_>) -> Result<Zeroizing<Vec<u8>>> {
    let mut value = Zeroizing::new(vec![0; claim.attribute_len()?]);
    claim.write_attribute(&mut value)?;
    if value.last() == Some(&0) {
        value.pop();
    }
    Ok(value)
}

fn consumed_row<W: Write>(
    out: &mut Output<'_, W>,
    attribute: Attribute<'_>,
    presentation: Option<Presentation<'_>>,
    scratch: &mut Option<ClaimScratch>,
) -> Result<()> {
    let display = presentation
        .map(|original| {
            let (mut workspace, limits) = scratch.get_or_insert_with(ClaimScratch::new).workspace();
            let Ok(claims) = workspace.presentation(original, limits) else {
                return Ok(None);
            };
            let field = credentials::value_string(attribute.value);
            let Some(name) = std::str::from_utf8(field.expose()).ok() else {
                return Ok(None);
            };
            claims
                .attributes()
                .find(|claim| claim.name.chars().eq(name.chars()))
                .map(|claim| claim_value(claim.value))
                .transpose()
        })
        .transpose()?
        .flatten();
    let value = match presentation {
        Some(_) => display.as_deref().map_or(b"???".as_slice(), Vec::as_slice),
        None => attribute_value(attribute),
    };
    let kind = credentials::attribute_type_name(attribute.kind)
        .unwrap_or("???")
        .as_bytes();
    let id = encoded_id(attribute.id)?;
    let flags = attribute.flags.to_string();
    let provenance = if presentation.is_some() {
        b"(ATTESTED)".as_slice()
    } else {
        b""
    };
    out.line(&[
        b"Name: ",
        attribute.name.bytes(),
        b"; Value: ",
        value,
        b" (",
        kind,
        b"); Flag ",
        flags.as_bytes(),
        b"; ID: ",
        &id,
        b" ",
        provenance,
    ])
}

struct ClaimScratch {
    payload: Zeroizing<Vec<u8>>,
    tokens: Zeroizing<Vec<credentials::Token>>,
    nesting: Zeroizing<Vec<credentials::Nest>>,
    limits: credentials::Limits,
}

impl ClaimScratch {
    fn new() -> Self {
        let limits = credentials::Limits::default();
        Self {
            payload: Zeroizing::new(vec![0; limits.payload_bytes]),
            tokens: Zeroizing::new(vec![credentials::Token::EMPTY; limits.nodes]),
            nesting: Zeroizing::new(vec![credentials::Nest::EMPTY; limits.depth]),
            limits,
        }
    }

    fn workspace(&mut self) -> (credentials::Workspace<'_>, credentials::Limits) {
        (
            credentials::Workspace::new(&mut self.payload, &mut self.tokens, &mut self.nesting),
            self.limits,
        )
    }
}
