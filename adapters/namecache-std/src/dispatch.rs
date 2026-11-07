//! Synchronous preflight and real memory effects. Native queue credit is reserved
//! before this effect; no data or mutation can migrate to another MQ.
use gnunet_namecache::Cache;
use gnunet_types::Error;
use gnunet_wire::official::namecache::{BLOCK_PREFIX, RESULT_LEN, Request, Response};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Kind {
    Lookup,
    Cache,
    Delete,
}
/// Real handler invocation/result, independent of preflight, queue or write.
#[derive(Clone, Copy, Debug)]
pub(super) enum Observation {
    Request(Kind),
    Found,
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Applied {
    pub rid: u32,
    pub kind: Kind,
    pub result: Option<i32>,
    pub size: usize,
}
pub(super) fn response_size(cache: &Cache, input: &[u8]) -> Result<usize, Error> {
    match Request::decode(input)? {
        Request::Lookup { query, .. } => {
            Ok(BLOCK_PREFIX + cache.lookup(query)?.map_or(0, |b| b.as_bytes().len()))
        }
        Request::Cache { .. } | Request::Delete { .. } => Ok(RESULT_LEN),
    }
}
pub(super) fn allocate(size: usize) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).map_err(|_| Error::Capacity)?;
    bytes.resize(size, 0);
    Ok(bytes)
}
#[cfg(test)]
pub(super) fn apply(cache: &mut Cache, input: &[u8], output: &mut [u8]) -> Result<Applied, Error> {
    apply_observed(cache, input, output, |_| {})
}
/// Production dispatch; the existing pure model uses the same implementation.
/// Observation cannot refuse/alter the original backend operation or result.
pub(super) fn apply_observed(
    cache: &mut Cache,
    input: &[u8],
    output: &mut [u8],
    mut observe: impl FnMut(Observation),
) -> Result<Applied, Error> {
    // Recheck before any effect, even if a caller supplies outdated preflight.
    if output.len() < response_size(cache, input)? {
        return Err(Error::Capacity);
    }
    let request = Request::decode(input)?;
    let kind = match request {
        Request::Lookup { .. } => Kind::Lookup,
        Request::Cache { .. } => Kind::Cache,
        Request::Delete { .. } => Kind::Delete,
    };
    // Count a real handler invocation before its actual backend result. In
    // particular CACHE/DELETE refusal/error is not a successful mutation but
    // still belongs to the official request counter. Preflight never counts.
    observe(Observation::Request(kind));
    let response = cache.handle(request)?;
    if matches!(response, Response::Lookup { block, .. } if !block.is_empty()) {
        observe(Observation::Found);
    }
    let (kind, result) = match response {
        Response::Lookup { .. } => (Kind::Lookup, None),
        Response::Cache { result, .. } => (Kind::Cache, Some(result)),
        Response::Delete { result, .. } => (Kind::Delete, Some(result)),
    };
    let rid = response.request_id();
    let size = response.encode(output)?;
    Ok(Applied {
        rid,
        kind,
        result,
        size,
    })
}
