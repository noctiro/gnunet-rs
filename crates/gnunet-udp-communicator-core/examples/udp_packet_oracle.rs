//! Finite cross-implementation packet observer, never a production C backend.
#![expect(
    clippy::print_stdout,
    reason = "Finite component observer emits public fields and checked counters"
)]
use gnunet_crypto::Entropy;
use gnunet_session_crypto::{
    exchange::{self, EcdhePublic},
    session,
    udp::DatagramKey,
};
use gnunet_types::Error;
use gnunet_udp_communicator_core::{
    Identity, handshake,
    wire::{self, Ack, Body, Control, Rekey},
};
use std::{fmt::Write as _, fs, path::Path};
use zeroize::Zeroizing;
struct Random;
impl Entropy for Random {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        getrandom::fill(b).map_err(|_| Error::Entropy)
    }
}
fn test(sequence: u32) -> [u8; 8] {
    let mut b = [0; 8];
    b[..2].copy_from_slice(&8u16.to_be_bytes());
    b[4..].copy_from_slice(&sequence.to_be_bytes());
    b
}
fn hex(b: &[u8]) -> Result<String, std::fmt::Error> {
    let mut s = String::new();
    for v in b {
        write!(s, "{v:02x}")?;
    }
    Ok(s)
}
fn body(
    control: Option<Rekey>,
    sequence: u32,
    n: usize,
    entropy: &mut impl Entropy,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut b = Zeroizing::new(vec![0; n]);
    let at = if let Some(rekey) = control {
        rekey.encode(&mut b)?
    } else {
        0
    };
    let end = at.checked_add(8).ok_or(Error::Overflow)?;
    if end > n {
        return Err(Error::Capacity);
    }
    b[at..end].copy_from_slice(&test(sequence));
    entropy.fill(&mut b[end..])?;
    let padding = n - end;
    if padding > 4 {
        let size = u16::try_from(padding).map_err(|_| Error::TooLarge)?;
        b[end..end + 2].copy_from_slice(&size.to_be_bytes());
        b[end + 2..end + 4].copy_from_slice(&wire::PAD.to_be_bytes());
    }
    Ok(b)
}
fn check_padding(padding: &[u8]) -> Result<(), Error> {
    if padding.len() <= 4
        || usize::from(u16::from_be_bytes([padding[0], padding[1]])) != padding.len()
        || u16::from_be_bytes([padding[2], padding[3]]) != wire::PAD
    {
        return Err(Error::Malformed);
    }
    Ok(())
}
fn read(dir: &Path, name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let path = dir.join(name);
    if fs::metadata(&path)?.len() > 65535 {
        return Err(Error::TooLarge.into());
    }
    Ok(fs::read(path)?)
}
fn emit(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(dir)?;
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let mut random = Random;
    let mut initial = vec![0; 192];
    let payload = body(None, 1, 40, &mut random)?;
    let (_, secret) = handshake::seal(
        &a,
        b.peer(),
        0x0102030405060708,
        &payload,
        &mut initial,
        &mut random,
        core::num::NonZeroUsize::new(128).ok_or(Error::InvalidInput)?,
    )?;
    let initial_cmac = secret.cmac;
    let initial_enc = secret.encapsulation;
    let master = secret.into_master();
    let old_key = DatagramKey::derive(&master, 1)?;
    let (rekey_enc, rekey_master) =
        exchange::kem_encapsulate_random(EcdhePublic::from_edwards(&b.peer())?, &mut random)?;
    let payload = body(Some(Rekey(*rekey_enc.as_bytes())), 2, 144, &mut random)?;
    let mut boxed = vec![0; 192];
    old_key.seal_box(&payload, &mut boxed)?;
    let new_key = DatagramKey::derive(&rekey_master, 1)?;
    let payload = body(None, 3, 80, &mut random)?;
    let mut rekey_box = vec![0; 128];
    new_key.seal_box(&payload, &mut rekey_box)?;
    let rekey_cmac = session::udp_cmac(&rekey_master)?;
    let mut ack = [0; 72];
    Ack {
        allowed: 128,
        cmac: initial_cmac,
    }
    .encode(&mut ack)?;
    let mut new_ack = [0; 72];
    Ack {
        allowed: 128,
        cmac: rekey_cmac,
    }
    .encode(&mut new_ack)?;
    for (name, bytes) in [
        ("initial.bin", initial.as_slice()),
        ("box.bin", boxed.as_slice()),
        ("rekey-box.bin", rekey_box.as_slice()),
        ("ack.bin", &ack),
        ("rekey-ack.bin", &new_ack),
    ] {
        fs::write(dir.join(name), bytes)?;
    }
    let metadata = format!(
        r#"{{"schema":1,"profile":"reference-0.29.1","sender":"{}","receiver":"{}","monotonic":"0102030405060708","initial_enc":"{}","initial_cmac":"{}","initial_kid_1":"{}","rekey_enc":"{}","rekey_cmac":"{}","rekey_kid_1":"{}","packets":{{"initial.bin":192,"box.bin":192,"rekey-box.bin":128,"ack.bin":72,"rekey-ack.bin":72}}}}
"#,
        hex(&a.peer())?,
        hex(&b.peer())?,
        hex(&initial_enc)?,
        hex(&initial_cmac)?,
        hex(old_key.kid())?,
        hex(rekey_enc.as_bytes())?,
        hex(&rekey_cmac)?,
        hex(new_key.kid())?
    );
    fs::write(dir.join("metadata.json"), metadata)?;
    println!(
        "{{\"status\":\"emitted\",\"initial\":1,\"box\":1,\"rekey_box\":1,\"ack\":1,\"rekey_ack\":1}}"
    );
    Ok(())
}
fn open(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let a = Identity::from_seed([3; 32]);
    let b = Identity::from_seed([5; 32]);
    let initial = read(dir, "initial.bin")?;
    if initial.len() != 192 {
        return Err(Error::Malformed.into());
    }
    let mut scratch = Zeroizing::new(vec![0; initial.len()]);
    let opened = handshake::open(&b, &initial, &mut scratch)?;
    if opened.confirmation.sender != a.peer() || opened.confirmation.monotonic != 0x0102030405060708
    {
        return Err(Error::Authentication.into());
    }
    let body = Body::decode(opened.body())?;
    check_padding(body.padding)?;
    if body.control.is_some() || body.message != Some(test(1).as_slice()) {
        return Err(Error::Malformed.into());
    }
    let secret = opened.into_secret()?;
    let initial_enc = secret.encapsulation;
    let master = secret.into_master();
    let ack = Ack::decode_backchannel(&read(dir, "ack.bin")?)?;
    if ack.allowed != 128 || ack.cmac != session::udp_cmac(&master)? {
        return Err(Error::Authentication.into());
    }
    let boxed = read(dir, "box.bin")?;
    if boxed.len() != 192 {
        return Err(Error::Malformed.into());
    }
    let key = DatagramKey::derive(&master, 1)?;
    let initial_kid = *key.kid();
    let n = key.open_box(&boxed, &mut scratch)?;
    let body = Body::decode(&scratch[..n])?;
    check_padding(body.padding)?;
    if body.message != Some(test(2).as_slice()) {
        return Err(Error::Malformed.into());
    }
    let enc = match body.control {
        Some(Control::Rekey(enc)) => enc,
        _ => return Err(Error::Malformed.into()),
    };
    let new_master = b.decapsulate_rekey(enc.0)?;
    let new_ack = Ack::decode_backchannel(&read(dir, "rekey-ack.bin")?)?;
    if new_ack.allowed != 128 || new_ack.cmac != session::udp_cmac(&new_master)? {
        return Err(Error::Authentication.into());
    }
    let rekey_box = read(dir, "rekey-box.bin")?;
    if rekey_box.len() != 128 {
        return Err(Error::Malformed.into());
    }
    let key = DatagramKey::derive(&new_master, 1)?;
    let rekey_kid = *key.kid();
    let n = key.open_box(&rekey_box, &mut scratch)?;
    let body = Body::decode(&scratch[..n])?;
    check_padding(body.padding)?;
    if body.control.is_some() || body.message != Some(test(3).as_slice()) {
        return Err(Error::Malformed.into());
    }
    let actual: serde_json::Value = serde_json::from_slice(&read(dir, "metadata.json")?)?;
    let expected = serde_json::json!({
        "schema": 1, "profile": "reference-0.29.1",
        "sender": hex(&a.peer())?, "receiver": hex(&b.peer())?,
        "monotonic": "0102030405060708", "initial_enc": hex(&initial_enc)?,
        "initial_cmac": hex(&ack.cmac)?, "initial_kid_1": hex(&initial_kid)?,
        "rekey_enc": hex(&enc.0)?, "rekey_cmac": hex(&new_ack.cmac)?,
        "rekey_kid_1": hex(&rekey_kid)?,
        "packets": {"initial.bin":192,"box.bin":192,"rekey-box.bin":128,
                    "ack.bin":72,"rekey-ack.bin":72}
    });
    if actual != expected {
        return Err("public metadata differs from authenticated fields".into());
    }
    println!(
        "{{\"status\":\"passed\",\"initial\":1,\"box\":1,\"rekey_box\":1,\"ack\":1,\"rekey_ack\":1}}"
    );
    Ok(())
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("expected emit NEW_DIR or open INPUT_DIR".into());
    }
    match args[0].to_str() {
        Some("emit") => emit(Path::new(&args[1])),
        Some("open") => open(Path::new(&args[1])),
        _ => Err("unknown packet command".into()),
    }
}
