use crate::{
    Failure,
    options::Print,
    run::{Facts, Guard},
};
use gnunet_crypto::EddsaPrivateKey;
use gnunet_gnsrecord::{decode_base32, encode_base32};
use gnunet_session_crypto::exchange::EcdheSecret;
use std::{
    io::{self, Write},
    path::Path,
};
use zeroize::Zeroizing;

mod namespace;
mod reader;
mod staging;
use reader::Reader;
pub(super) use staging::Staging;

pub(super) struct Vanity {
    target: [u8; 32],
    bits: usize,
}
impl Vanity {
    pub fn new(prefix: &[u8]) -> Result<Self, Failure> {
        if prefix.len() > 52 {
            return Err("vanity prefix exceeds 256 public-key bits".into());
        }
        let mut encoded = [b'0'; 52];
        encoded[..prefix.len()].copy_from_slice(prefix);
        let mut target = [0u8; 32];
        decode_base32(&encoded, &mut target)?;
        Ok(Self {
            target,
            bits: prefix.len().saturating_mul(5).min(256),
        })
    }
    fn matches(&self, key: &[u8; 32]) -> bool {
        let whole = self.bits / 8;
        let remaining = self.bits % 8;
        key[..whole] == self.target[..whole]
            && (remaining == 0
                || (key[whole] ^ self.target[whole]) & (0xff << (8 - remaining)) == 0)
    }
}
async fn bytes(
    w: &mut dyn Write,
    value: &[u8],
    guard: &mut Guard,
    count: &mut u128,
) -> Result<(), Failure> {
    let mut at = 0;
    while at < value.len() {
        guard.check().await?;
        match w.write(&value[at..]) {
            Ok(0) => {
                return Err(
                    io::Error::new(io::ErrorKind::WriteZero, "zero ECC output write").into(),
                );
            }
            Ok(n) => {
                at += n;
                *count = count
                    .checked_add(n as u128)
                    .ok_or("ECC output count overflow")?;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                tokio::task::yield_now().await;
                continue;
            }
            Err(e) => return Err(e.into()),
        }
        // Positive/whole output facts precede a late cancellation/clock error.
        guard.check().await?;
    }
    Ok(())
}
async fn flush(w: &mut dyn Write, guard: &mut Guard) -> Result<(), Failure> {
    guard.check().await?;
    w.flush()?;
    guard.check().await
}
async fn base32(
    prefix: &[u8],
    value: &[u8],
    w: &mut dyn Write,
    guard: &mut Guard,
    count: &mut u128,
) -> Result<(), Failure> {
    let mut line = Zeroizing::new([0u8; 160]);
    line.get_mut(..prefix.len())
        .ok_or("ECC output prefix bound")?
        .copy_from_slice(prefix);
    let n = encode_base32(
        value,
        line.get_mut(prefix.len()..).ok_or("ECC output bound")?,
    )?;
    let end = prefix
        .len()
        .checked_add(n)
        .ok_or("ECC output size overflow")?;
    *line.get_mut(end).ok_or("ECC output bound")? = b'\n';
    bytes(w, &line[..end + 1], guard, count).await
}
async fn hexadecimal(
    prefix: &[u8],
    value: &[u8],
    w: &mut dyn Write,
    guard: &mut Guard,
    count: &mut u128,
) -> Result<(), Failure> {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut line = Zeroizing::new([0u8; 160]);
    let end = value
        .len()
        .checked_mul(2)
        .and_then(|n| n.checked_add(prefix.len()))
        .ok_or("ECC hex size overflow")?;
    if end >= line.len() {
        return Err("ECC hex output bound".into());
    }
    line[..prefix.len()].copy_from_slice(prefix);
    for (i, b) in value.iter().enumerate() {
        line[prefix.len() + i * 2] = HEX[usize::from(b >> 4)];
        line[prefix.len() + i * 2 + 1] = HEX[usize::from(b & 15)];
    }
    line[end] = b'\n';
    bytes(w, &line[..end + 1], guard, count).await
}
pub(super) async fn inspect(
    path: &Path,
    maximum: Option<u32>,
    form: Option<Print>,
    guard: &mut Guard,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
    facts: &mut Facts,
) -> Result<(), Failure> {
    guard.check().await?;
    let mut input = Reader::open(path)?;
    guard.check().await?;
    let rows = maximum.map_or(input.rows, |max| input.rows.min(u64::from(max)));
    for index in 0..rows {
        let seed = input.record(guard, facts).await?;
        if maximum.is_some() {
            let key = EddsaPrivateKey::from_seed(*seed);
            let prefix = format!("{index:4}: ");
            base32(
                prefix.as_bytes(),
                key.public_key().as_bytes(),
                stderr,
                guard,
                &mut facts.stderr_bytes,
            )
            .await?;
        } else {
            match form.ok_or("missing ECC print selection")? {
                Print::Private => {
                    base32(b"", seed.as_ref(), stdout, guard, &mut facts.stdout_bytes).await?
                }
                Print::Public | Print::Hex => {
                    let key = EddsaPrivateKey::from_seed(*seed);
                    guard.check().await?;
                    let public = key.public_key();
                    match form {
                        Some(Print::Hex) => {
                            hexadecimal(
                                b"HEX:: ",
                                public.as_bytes(),
                                stdout,
                                guard,
                                &mut facts.stdout_bytes,
                            )
                            .await?
                        }
                        _ => {
                            base32(
                                b"",
                                public.as_bytes(),
                                stdout,
                                guard,
                                &mut facts.stdout_bytes,
                            )
                            .await?
                        }
                    }
                }
            }
        }
        guard.turn().await?;
    }
    guard.check().await?;
    input.verify()?;
    guard.check().await?;
    if maximum.is_some() {
        flush(stderr, guard).await
    } else {
        flush(stdout, guard).await
    }
}
pub(super) async fn generate(
    path: &Path,
    count: u32,
    vanity: Option<&Vanity>,
    owner: &mut Option<Staging>,
    guard: &mut Guard,
    stderr: &mut dyn Write,
    facts: &mut Facts,
) -> Result<(), Failure> {
    guard.check().await?;
    Staging::create(path, owner)?;
    guard.check().await?;
    let start = format!("Generating {count} original raw32 keys\n");
    bytes(stderr, start.as_bytes(), guard, &mut facts.stderr_bytes).await?;
    for _ in 0..count {
        loop {
            let seed = guard.candidate(facts).await?;
            let accepted = vanity.is_none_or(|prefix| {
                let key = EddsaPrivateKey::from_seed(*seed);
                prefix.matches(key.public_key().as_bytes())
            });
            guard.check().await?;
            if accepted {
                facts.keys_generated = facts
                    .keys_generated
                    .checked_add(1)
                    .ok_or("ECC generated count overflow")?;
                owner
                    .as_mut()
                    .ok_or("missing ECC staging owner")?
                    .write(&seed, guard, facts)
                    .await?;
                guard.turn().await?;
                break;
            }
            guard.turn().await?;
        }
    }
    owner
        .as_mut()
        .ok_or("missing ECC staging owner")?
        .publish(guard, facts)
        .await?;
    bytes(
        stderr,
        b"Finished complete raw32 publication\n",
        guard,
        &mut facts.stderr_bytes,
    )
    .await?;
    flush(stderr, guard).await
}
pub(super) async fn examples(
    guard: &mut Guard,
    stdout: &mut dyn Write,
    facts: &mut Facts,
) -> Result<(), Failure> {
    let first = guard.candidate(facts).await?;
    let key1 = EcdheSecret::from_bytes(*first);
    guard.check().await?;
    let second = guard.candidate(facts).await?;
    let key2 = EcdheSecret::from_bytes(*second);
    guard.check().await?;
    let public1 = key1.public_key();
    guard.check().await?;
    let public2 = key2.public_key();
    guard.check().await?;
    bytes(stdout, b"ECDHE key 1:\n", guard, &mut facts.stdout_bytes).await?;
    base32(
        b"private: ",
        first.as_ref(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    hexadecimal(
        b"private(hex): ",
        first.as_ref(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    base32(
        b"public: ",
        public1.as_bytes(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    hexadecimal(
        b"public(hex): ",
        public1.as_bytes(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    bytes(stdout, b"ECDHE key 2:\n", guard, &mut facts.stdout_bytes).await?;
    base32(
        b"private: ",
        second.as_ref(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    hexadecimal(
        b"private(hex): ",
        second.as_ref(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    base32(
        b"public: ",
        public2.as_bytes(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    hexadecimal(
        b"public(hex): ",
        public2.as_bytes(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    guard.check().await?;
    let shared = key1.exchange_hashed(public2)?.into_secret_bytes();
    guard.check().await?;
    base32(
        b"ECDH shared secret: ",
        shared.as_ref(),
        stdout,
        guard,
        &mut facts.stdout_bytes,
    )
    .await?;
    flush(stdout, guard).await
}
