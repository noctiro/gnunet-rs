//! Safe host construction probe. No OS DNS, native lookup, networking or C calls.
#[path = "../tests/support/mod.rs"]
mod support;
use gnunet_resolver_service_core::{
    owner::{Effect, Resolver},
    storage::Limits,
};
use gnunet_types::Error;
use std::io::{self, Write};
fn run() -> Result<String, Error> {
    let geometry = [64, 128, 1024, 1025, 4096, 512];
    let byte_capacity = 8 * 1024 * 1024;
    let mut backing = support::Store::new(geometry, byte_capacity)?;
    let mut staging = support::Store::new(geometry, byte_capacity)?;
    let backing_reserved = backing.allocated_bytes();
    let staging_reserved = staging.allocated_bytes();
    let mut core = Resolver::new(
        backing.buffers(),
        Limits {
            max_name_bytes: 65535,
            max_record_bytes: 65535,
            cname_hops: 32,
        },
        1,
    )?;
    let mut scratch = core.make_scratch(staging.buffers())?;
    core.connect()?;
    core.shutdown(&mut scratch)?;
    let ticket = core.take_effect()?.ok_or(Error::NotReady)?;
    if core.effect(ticket)? != Effect::Stop {
        return Err(Error::Malformed);
    }
    core.release_effect(ticket)?;
    if core.take_effect()?.is_some() {
        return Err(Error::Malformed);
    }
    Ok(format!(
        "{{\"constructed\":true,\"stop_released\":true,\"control_bytes\":{},\"geometry\":{:?},\"max_record_bytes\":65535,\"byte_pool_per_store\":{},\"backing_vector_reserved_bytes\":{},\"staging_vector_reserved_bytes\":{},\"pair_vector_reserved_bytes\":{},\"excludes_allocator_overhead_and_RSS\":true,\"excludes_external_text_and_DNS_parse_scratch\":true}}",
        Resolver::control_bytes(),
        geometry,
        byte_capacity,
        backing_reserved,
        staging_reserved,
        backing_reserved + staging_reserved
    ))
}
fn main() -> io::Result<()> {
    let result = run().map_err(|e| io::Error::other(format!("{e:?}")))?;
    writeln!(io::stdout().lock(), "{result}")
}
