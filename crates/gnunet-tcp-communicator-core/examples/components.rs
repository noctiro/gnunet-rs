//! Deterministic utility-component observer, never a TCP communicator daemon.
use gnunet_crypto::EddsaPrivateKey;
use gnunet_session_crypto::Prk;
use gnunet_tcp_communicator_core::{
    record::Direction,
    wire::{self, Representative},
};
use std::{
    fmt::Write as _,
    io::{self, Write as _},
};
fn hex(bytes: &[u8]) -> Result<String, std::fmt::Error> {
    let mut s = String::new();
    for b in bytes {
        write!(&mut s, "{b:02x}")?;
    }
    Ok(s)
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let a = EddsaPrivateKey::from_seed([1; 32]);
    let b = EddsaPrivateKey::from_seed([2; 32]);
    let c = wire::confirmation(&a, b.public_key(), Representative([3; 32]), 123, &[4; 32])?;
    let ack = wire::acknowledgement(&a, b.public_key(), 1, &[4; 32])?;
    let rekey = wire::rekey(&a, b.public_key(), &[5; 32], 7)?;
    let payload = [0, 8, 0, 17, 1, 2, 3, 4];
    let p = Prk::from_bytes([42; 32]);
    let new = Prk::from_bytes([19; 32]);
    let mut sender = Direction::new(&p)?;
    let mut one = [0; 44];
    let mut two = [0; 44];
    let mut fin = [0; 36];
    sender.seal_box(&payload, &mut one)?;
    sender.seal_box(&payload, &mut two)?;
    sender.seal_finish(&mut fin)?;
    let mut sender = Direction::new(&p)?;
    let mut encrypted_ack = ack;
    sender.handshake_fragment(&mut encrypted_ack)?;
    let mut after_ack = [0; 44];
    sender.seal_box(&payload, &mut after_ack)?;
    let mut sender = Direction::new(&p)?;
    let mut encrypted_rekey = [0; 140];
    sender.seal_rekey(&rekey, &new, &mut encrypted_rekey)?;
    let mut after_rekey = [0; 44];
    sender.seal_box(&payload, &mut after_rekey)?;
    let special = gnunet_session_crypto::elligator::Secret::from_bytes([3; 32]);
    let (initial, mut continuation) = gnunet_tcp_communicator_core::initial::prepare(
        &a,
        b.public_key(),
        &special,
        6,
        123,
        &[4; 32],
    )?;
    let mut initial_following_ack = ack;
    continuation.handshake_fragment(&mut initial_following_ack)?;
    let mut out = io::stdout().lock();
    writeln!(
        out,
        "{{\"kind\":\"rust-components\",\"initial_kx\":\"{}\",\"initial_following_ack\":\"{}\",\"confirmation\":\"{}\",\"ack\":\"{}\",\"rekey\":\"{}\",\"box1\":\"{}\",\"box2\":\"{}\",\"finish\":\"{}\",\"encrypted_ack\":\"{}\",\"after_ack\":\"{}\",\"encrypted_rekey\":\"{}\",\"after_rekey\":\"{}\",\"sizes\":[144,112,112,136,168,140,36,140,36,36]}}",
        hex(&initial)?,
        hex(&initial_following_ack)?,
        hex(&c)?,
        hex(&ack)?,
        hex(&rekey)?,
        hex(&one)?,
        hex(&two)?,
        hex(&fin)?,
        hex(&encrypted_ack)?,
        hex(&after_ack)?,
        hex(&encrypted_rekey)?,
        hex(&after_rekey)?
    )?;
    Ok(())
}
