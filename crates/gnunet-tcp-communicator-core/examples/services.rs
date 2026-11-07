//! Finite public service-wire/key derivation observer; no normal-daemon claim.
#![expect(
    clippy::print_stdout,
    reason = "Standalone observer emits exact public JSON fields"
)]
use gnunet_crypto::hash512;
use gnunet_tcp_communicator_core::{
    nat, services,
    session::{KeyRing, ReplayKind},
};
use gnunet_types::Error;
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn main() -> Result<(), Error> {
    let hash = hash512(b"");
    let mut update = [0; 72];
    update[..2].copy_from_slice(&72u16.to_be_bytes());
    update[2..4].copy_from_slice(&1831u16.to_be_bytes());
    update[4..68].copy_from_slice(&hash);
    let ring: KeyRing = services::Pils::decode(&update)?.key_ring(&[22; 32])?;
    let mut out = [0; 512];
    let n = services::replay_store(
        0x10203040,
        ring.public(),
        ReplayKind::Handshake,
        123456789u64.to_be_bytes(),
        &mut out,
    )?;
    let store = hex(&out[..n]);
    let profile = if cfg!(target_os = "macos") {
        nat::Profile::Darwin
    } else {
        nat::Profile::Linux
    };
    let mut raw = [0; 28];
    let n = nat::address(
        profile,
        "127.0.0.1:80".parse().map_err(|_| Error::InvalidInput)?,
        &mut raw,
    )?;
    let native = nat::Native::parse(profile, &raw[..n])?;
    let n = nat::register(&[native], &mut out)?;
    println!(
        "{{\"sizes\":[60,48,64,88,72,10],\"pils_public\":\"{}\",\"store\":\"{}\",\"native_v4\":\"{}\",\"nat_register_layout\":\"{}\"}}",
        hex(ring.public().as_bytes()),
        store,
        hex(native.bytes()),
        hex(&out[..n])
    );
    Ok(())
}
