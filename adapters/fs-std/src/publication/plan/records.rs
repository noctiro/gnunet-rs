//! Original-context UBLOCK preparation and strict selected-field reauthentication.
use super::{Artifact, Error, Limits, Payload, Plan, Put, owned, selected_metadata, uri_bytes};
use crate::{Control, Progress, Repository, namespace::key::KeyFile};
use gnunet_fs::{
    Keywords, Uri, metadata as md,
    ublock::{self, Context, Publisher},
};
use gnunet_fs_codec::Inflate;
use std::mem::size_of;
fn wire_limits(limits: Limits) -> ublock::Limits {
    ublock::Limits {
        max_wire_bytes: limits
            .ublock
            .max_wire_bytes
            .min(limits.max_payload_bytes)
            .min(gnunet_wire::official::datastore::MAX_VALUE_BYTES),
        ..limits.ublock
    }
}
fn budget(plan: &Plan, count: usize, bytes: usize, limits: Limits) -> Result<(), Error> {
    if count == 0
        || count > limits.max_puts
        || plan
            .retained_bytes()?
            .checked_add(count.checked_mul(size_of::<Put>()).ok_or(Error::Limit)?)
            .is_none_or(|n| n > limits.max_plan_bytes)
        || (count as u128)
            .checked_mul(bytes as u128)
            .is_none_or(|n| n > limits.max_stored_bytes)
    {
        return Err(Error::Limit);
    }
    Ok(())
}
fn exact_wire(
    update: &[u8],
    target: &[u8],
    metadata: Option<&[u8]>,
    limits: Limits,
) -> Result<usize, Error> {
    if update.contains(&0) {
        return Err(ublock::Error::Update.into());
    }
    if update.len() > ublock::PUBLISHER_BYTES {
        return Err(Error::Limit);
    }
    let n = ublock::HEADER_BYTES
        .checked_add(update.len())
        .and_then(|n| n.checked_add(2))
        .and_then(|n| n.checked_add(target.len()))
        .and_then(|n| n.checked_add(metadata.map_or(0, <[u8]>::len)))
        .and_then(|n| n.checked_add(ublock::TAG_BYTES))
        .ok_or(Error::Limit)?;
    if n > wire_limits(limits).max_wire_bytes || n > ublock::PUBLISHER_BYTES + ublock::TAG_BYTES {
        return Err(Error::Limit);
    }
    Ok(n)
}
fn canonical(raw: &[u8], limits: Limits) -> Result<(), Error> {
    if raw.len() > limits.ublock.uri.max_input_bytes || raw.len() > limits.max_plan_bytes {
        return Err(Error::Limit);
    }
    let uri = Uri::parse(raw, limits.ublock.uri)?;
    if uri_bytes(uri, limits)? != raw {
        return Err(Error::Binding);
    }
    Ok(())
}
fn scratch(raw: Option<&[u8]>, limits: Limits) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    if let Some(raw) = raw {
        if raw.len() > limits.ublock.metadata.max_coded_bytes {
            return Err(Error::Limit);
        }
        let header = raw.get(..md::HEADER_BYTES).ok_or(md::Error::Truncated)?;
        let mut version = [0; 4];
        version.copy_from_slice(&header[..4]);
        let mut length = [0; 4];
        length.copy_from_slice(&header[8..12]);
        let needed = if u32::from_be_bytes(version) & md::COMPRESSED != 0 {
            u32::from_be_bytes(length) as usize
        } else {
            0
        };
        if needed > limits.ublock.metadata.max_plain_bytes {
            return Err(Error::Limit);
        }
        out.try_reserve_exact(needed).map_err(|_| Error::Limit)?;
        out.resize(needed, 0);
        if !matches!(
            md::decode(
                raw,
                &mut out,
                &mut Inflate::new(),
                limits.ublock.metadata,
                md::Mode::Strict
            )?,
            md::Decoded::Present(_)
        ) {
            return Err(Error::Binding);
        }
    }
    Ok(out)
}
fn row(put: &Put, query: &[u8; 64], bytes: usize) -> Result<(), Error> {
    if put.kind != 9 || put.position.is_some() || put.key != *query || put.payload.bytes != bytes {
        return Err(Error::Binding);
    }
    Ok(())
}
fn write(
    repo: &mut Repository,
    publisher: &Publisher<'_>,
    update: &[u8],
    target: Uri<'_>,
    metadata: Option<&md::Plan<'_>>,
    wire: &mut [u8],
) -> Result<Put, Error> {
    let sealed = publisher.seal(update, target, metadata, wire)?;
    let key = *sealed.query();
    let bytes = sealed.bytes().len();
    let (hash, _) = repo.insert_payload(sealed.bytes())?;
    Ok(Put {
        kind: 9,
        key,
        payload: Payload { hash, bytes },
        position: None,
    })
}
/// Prepare every ordered KSK term, including repeated labels, as a real signed
/// type9 block. Only immutable payloads are stored; no DATASTORE request is sent.
pub fn prepare_keywords(
    repo: &mut Repository,
    keywords: Keywords<'_>,
    target: Uri<'_>,
    metadata: Option<&md::Plan<'_>>,
    limits: Limits,
) -> Result<Plan, Error> {
    if keywords.is_empty()
        || keywords.len() > limits.max_puts
        || keywords.len() > limits.ublock.uri.max_keywords
    {
        return Err(Error::Limit);
    }
    for term in keywords.iter() {
        if term.len() > limits.ublock.max_label_bytes {
            return Err(Error::Limit);
        }
    }
    let query_uri = uri_bytes(Uri::Keywords(keywords), limits)?;
    let target_uri = uri_bytes(target, limits)?;
    let selected = selected_metadata(metadata, limits)?;
    let bytes = exact_wire(b"", &target_uri, selected.as_deref(), limits)?;
    let mut plan = Plan {
        artifact: Artifact::Keywords {
            query_uri,
            target_uri,
            metadata: selected,
        },
        puts: Vec::new(),
    };
    budget(&plan, keywords.len(), bytes, limits)?;
    plan.puts
        .try_reserve_exact(keywords.len())
        .map_err(|_| Error::Limit)?;
    let mut wire = Vec::new();
    wire.try_reserve_exact(bytes).map_err(|_| Error::Limit)?;
    wire.resize(bytes, 0);
    for term in keywords.iter() {
        let mut label = Vec::new();
        label
            .try_reserve_exact(term.len())
            .map_err(|_| Error::Limit)?;
        label.resize(term.len(), 0);
        term.write(&mut label)?;
        let publisher = Publisher::keyword(&label, wire_limits(limits))?;
        plan.puts
            .push(write(repo, &publisher, b"", target, metadata, &mut wire)?);
    }
    plan.validate(limits)?;
    Ok(plan)
}
/// Prepare one actual namespace signature using the selected revalidated key.
/// The task retains only its public identity and sealed payload, never the seed.
/// This wire-only plan does not persist a managed namespace update graph.
pub fn prepare_namespace(
    repo: &mut Repository,
    key: &KeyFile,
    identifier: &[u8],
    update: &[u8],
    target: Uri<'_>,
    metadata: Option<&md::Plan<'_>>,
    limits: Limits,
) -> Result<Plan, Error> {
    if identifier.contains(&0) {
        return Err(ublock::Error::Label.into());
    }
    if identifier.len() > limits.ublock.max_label_bytes {
        return Err(Error::Limit);
    }
    key.revalidate()?;
    let target_uri = uri_bytes(target, limits)?;
    let selected = selected_metadata(metadata, limits)?;
    let bytes = exact_wire(update, &target_uri, selected.as_deref(), limits)?;
    let mut plan = Plan {
        artifact: Artifact::Namespace {
            public: key.public_key(),
            identifier: owned(identifier)?,
            update: owned(update)?,
            target_uri,
            metadata: selected,
        },
        puts: Vec::new(),
    };
    budget(&plan, 1, bytes, limits)?;
    plan.puts.try_reserve_exact(1).map_err(|_| Error::Limit)?;
    let mut wire = Vec::new();
    wire.try_reserve_exact(bytes).map_err(|_| Error::Limit)?;
    wire.resize(bytes, 0);
    let publisher = Publisher::namespace(key.secret(), identifier, wire_limits(limits))?;
    plan.puts.push(write(
        repo, &publisher, update, target, metadata, &mut wire,
    )?);
    key.revalidate()?;
    plan.validate(limits)?;
    Ok(plan)
}
pub(super) fn validate(plan: &Plan, limits: Limits) -> Result<(), Error> {
    match &plan.artifact {
        Artifact::Keywords {
            query_uri,
            target_uri,
            metadata,
        } => {
            canonical(query_uri, limits)?;
            canonical(target_uri, limits)?;
            let _scratch = scratch(metadata.as_deref(), limits)?;
            let Uri::Keywords(keywords) = Uri::parse(query_uri, limits.ublock.uri)? else {
                return Err(Error::Binding);
            };
            if keywords.len() != plan.puts.len() {
                return Err(Error::Binding);
            }
            let bytes = exact_wire(b"", target_uri, metadata.as_deref(), limits)?;
            for (term, put) in keywords.iter().zip(&plan.puts) {
                if term.len() > limits.ublock.max_label_bytes {
                    return Err(Error::Limit);
                }
                let mut label = Vec::new();
                label
                    .try_reserve_exact(term.len())
                    .map_err(|_| Error::Limit)?;
                label.resize(term.len(), 0);
                term.write(&mut label)?;
                row(
                    put,
                    Context::keyword(&label, wire_limits(limits))?.query(),
                    bytes,
                )?;
            }
        }
        Artifact::Namespace {
            public,
            identifier,
            update,
            target_uri,
            metadata,
        } => {
            if plan.puts.len() != 1 {
                return Err(Error::Binding);
            }
            canonical(target_uri, limits)?;
            let _scratch = scratch(metadata.as_deref(), limits)?;
            let bytes = exact_wire(update, target_uri, metadata.as_deref(), limits)?;
            row(
                &plan.puts[0],
                Context::namespace(public, identifier, wire_limits(limits))?.query(),
                bytes,
            )?;
        }
        Artifact::File(_) | Artifact::IndexedFile { .. } | Artifact::Tree(_) => {
            return Err(Error::Binding);
        }
    }
    Ok(())
}
struct Verifier {
    wire: Vec<u8>,
    plain: Vec<u8>,
    metadata: Vec<u8>,
    inflater: Inflate,
}
impl Verifier {
    fn new(metadata: Option<&[u8]>, limits: Limits) -> Result<Self, Error> {
        let n = wire_limits(limits).max_wire_bytes;
        if n < ublock::HEADER_BYTES + ublock::TAG_BYTES + 2 {
            return Err(Error::Limit);
        }
        let mut wire = Vec::new();
        wire.try_reserve_exact(n).map_err(|_| Error::Limit)?;
        wire.resize(n, 0);
        let mut plain = Vec::new();
        plain.try_reserve_exact(n).map_err(|_| Error::Limit)?;
        plain.resize(n, 0);
        Ok(Self {
            wire,
            plain,
            metadata: scratch(metadata, limits)?,
            inflater: Inflate::new(),
        })
    }
    fn check(
        &mut self,
        repo: &mut Repository,
        put: &Put,
        context: &Context<'_>,
        update: &[u8],
        target: &[u8],
        metadata: Option<&[u8]>,
    ) -> Result<(), Error> {
        let n = repo.read_payload(&put.payload.hash, &mut self.wire)?;
        if n != put.payload.bytes || context.query() != &put.key {
            return Err(Error::Binding);
        }
        let plain = context.open(&self.wire[..n], &mut self.plain)?;
        let record = plain.decode(&mut self.metadata, &mut self.inflater, md::Mode::Strict)?;
        if record.update_identifier() != update
            || record.raw_uri() != target
            || record.raw_metadata() != metadata.unwrap_or_default()
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
pub(super) fn verify(
    plan: &Plan,
    repo: &mut Repository,
    limits: Limits,
    control: &mut impl FnMut(Progress) -> Control,
) -> Result<(), Error> {
    let mut progress = Progress::default();
    match &plan.artifact {
        Artifact::Keywords {
            query_uri,
            target_uri,
            metadata,
        } => {
            let Uri::Keywords(keywords) = Uri::parse(query_uri, limits.ublock.uri)? else {
                return Err(Error::Binding);
            };
            let mut verifier = Verifier::new(metadata.as_deref(), limits)?;
            for (term, put) in keywords.iter().zip(&plan.puts) {
                if control(progress) == Control::Cancel {
                    return Err(crate::Error::Cancelled.into());
                }
                let mut label = Vec::new();
                label
                    .try_reserve_exact(term.len())
                    .map_err(|_| Error::Limit)?;
                label.resize(term.len(), 0);
                term.write(&mut label)?;
                verifier.check(
                    repo,
                    put,
                    &Context::keyword(&label, wire_limits(limits))?,
                    b"",
                    target_uri,
                    metadata.as_deref(),
                )?;
                progress.blocks += 1;
                progress.encoded_bytes += put.payload.bytes as u128;
            }
        }
        Artifact::Namespace {
            public,
            identifier,
            update,
            target_uri,
            metadata,
        } => {
            if control(progress) == Control::Cancel {
                return Err(crate::Error::Cancelled.into());
            }
            let mut verifier = Verifier::new(metadata.as_deref(), limits)?;
            verifier.check(
                repo,
                &plan.puts[0],
                &Context::namespace(public, identifier, wire_limits(limits))?,
                update,
                target_uri,
                metadata.as_deref(),
            )?;
            progress.blocks = 1;
            progress.encoded_bytes = plan.puts[0].payload.bytes as u128;
        }
        Artifact::File(_) | Artifact::IndexedFile { .. } | Artifact::Tree(_) => {
            return Err(Error::Binding);
        }
    }
    if control(progress) == Control::Cancel {
        return Err(crate::Error::Cancelled.into());
    }
    Ok(())
}
