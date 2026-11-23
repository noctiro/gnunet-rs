//! Test-only line control stream matching normal C oracle calls, not a wire API.
use gnunet_block::{
    BlockType, GroupState, Hash, ReturnValue,
    bloom::{BloomGroup, NativeEndian, compute_size, mingle_hash},
    plugins::{Context, GroupSizing, Plugin, RevocationConfig, Work},
    pow,
};
use std::{
    error::Error,
    io::{self, BufRead, Write},
};
fn decode(value: &str) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
    if value == "-" {
        return Ok(None);
    }
    if !value.len().is_multiple_of(2) {
        return Err("bad fixture hex".into());
    }
    let mut out = Vec::with_capacity(value.len() / 2);
    for i in (0..value.len()).step_by(2) {
        out.push(u8::from_str_radix(&value[i..i + 2], 16)?);
    }
    Ok(Some(out))
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn nullable() -> Result<String, Box<dyn Error>> {
    use gnunet_block::{
        MergeOutcome, bloom::test_and_set, group_destroy, group_merge, group_serialize,
        group_set_seen,
    };
    use std::cell::Cell;
    struct Dummy<'a>(&'a Cell<u32>);
    impl Drop for Dummy<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    impl GroupState for Dummy<'_> {
        fn block_type(&self) -> BlockType {
            BlockType::TEST
        }
        fn serialize_into(&self, _: &mut [u8]) -> Result<Option<usize>, gnunet_types::Error> {
            Ok(None)
        }
        fn mark_seen(&mut self, _: &[Hash]) -> gnunet_block::MarkSeen {
            gnunet_block::MarkSeen::Unsupported
        }
        fn has_merge(&self) -> bool {
            false
        }
        fn merge_from(&mut self, _: &Self) -> Result<ReturnValue, gnunet_types::Error> {
            Err(gnunet_types::Error::Unsupported)
        }
    }
    let mut output = [0xa5];
    let serial = group_serialize::<Dummy<'_>>(None, &mut output)?;
    let seen = group_set_seen::<Dummy<'_>>(None, &[]);
    let duplicate = test_and_set(None, &[0; 64]);
    let merge = match group_merge::<Dummy<'_>>(None, None)? {
        MergeOutcome::Consumed(value) => value,
        _ => return Err("nullmerge".into()),
    };
    let count = Cell::new(0);
    let mut left = Dummy(&count);
    let right = Dummy(&count);
    let result = group_merge(Some(&mut left), Some(right))?;
    let retained = count.get();
    let (no, right) = match result {
        MergeOutcome::Unsupported(right) => (ReturnValue::SysErr, right),
        _ => return Err("nocallback".into()),
    };
    group_destroy(Some(right));
    group_destroy(Some(left));
    Ok(format!(
        "N {} {} {} {} {} {} {} {}",
        u8::from(serial.is_some()),
        serial.unwrap_or(0),
        seen as i32,
        u8::from(duplicate),
        merge as i32,
        no as i32,
        retained,
        count.get()
    ))
}
fn consumed_negative_merge() -> Result<String, Box<dyn Error>> {
    use gnunet_block::{MergeOutcome, group_destroy, group_merge};
    use std::cell::Cell;
    struct G<'a>(&'a Cell<u32>);
    impl Drop for G<'_> {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }
    impl GroupState for G<'_> {
        fn block_type(&self) -> BlockType {
            BlockType::TEST
        }
        fn serialize_into(&self, _: &mut [u8]) -> Result<Option<usize>, gnunet_types::Error> {
            Ok(None)
        }
        fn mark_seen(&mut self, _: &[Hash]) -> gnunet_block::MarkSeen {
            gnunet_block::MarkSeen::Unsupported
        }
        fn has_merge(&self) -> bool {
            true
        }
        fn merge_from(&mut self, _: &Self) -> Result<ReturnValue, gnunet_types::Error> {
            Ok(ReturnValue::No)
        }
    }
    let drops = Cell::new(0);
    let mut a = G(&drops);
    let b = G(&drops);
    let result = match group_merge(Some(&mut a), Some(b))? {
        MergeOutcome::Consumed(code) => code,
        _ => return Err("unexpected merge".into()),
    };
    let consumed = drops.get();
    group_destroy(Some(a));
    Ok(format!("L {} {} {}", result as i32, consumed, drops.get()))
}
fn run() -> Result<(), Box<dyn Error>> {
    let utc: u64 = std::env::args()
        .nth(1)
        .ok_or("missing explicit UTC")?
        .parse()?;
    let profile = match std::env::args().nth(2).as_deref() {
        Some("deterministic") => gnunet_hello::SignatureProfile::DeterministicPidDerivation,
        Some("normal") => gnunet_hello::SignatureProfile::Gnunet029,
        _ => return Err("missing explicit HELLO compilation profile".into()),
    };
    let mut plugins = [
        Plugin::Test,
        Plugin::Dht,
        Plugin::Fs,
        Plugin::Gns,
        Plugin::Dns,
        Plugin::Regex,
        Plugin::Revocation(RevocationConfig {
            matching_bits: 0,
            epoch_duration: 86400000000,
        }),
        Plugin::SetIntersection,
        Plugin::SetUnion,
    ];
    let mut memory = vec![pow::Block::new(); pow::MEMORY_BLOCKS];
    let mut addresses = vec![0; 65535];
    let mut stdout = io::stdout().lock();
    for line in io::stdin().lock().lines() {
        let line = line?;
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.is_empty() {
            continue;
        }
        let context = Context::new(&plugins, NativeEndian::native());
        let output = match fields[0] {
            "T" => {
                plugins[6] = if fields[1] == "-" || fields[2] == "-" {
                    Plugin::Test
                } else {
                    Plugin::Revocation(RevocationConfig::from_native_values(
                        fields[1].parse()?,
                        fields[2].parse()?,
                    ))
                };
                "T".into()
            }
            "S" => format!("S {}", compute_size(fields[1].parse()?, fields[2].parse()?)),
            "M" => {
                let hash: Hash = decode(fields[2])?
                    .ok_or("missinghash")?
                    .try_into()
                    .map_err(|_| "hashlen")?;
                format!(
                    "M {}",
                    hex(&mingle_hash(
                        &hash,
                        fields[1].parse()?,
                        NativeEndian::native()
                    ))
                )
            }
            "P" => {
                let salt = decode(fields[1])?
                    .ok_or("missingsalt")?
                    .try_into()
                    .map_err(|_| "saltlen")?;
                let input = decode(fields[2])?.unwrap_or_default();
                let mut out = [0; 64];
                pow::hash(&salt, &input, &mut out, &mut memory)?;
                format!("P {}", hex(&out))
            }
            "B" => {
                let size: usize = fields[1].parse()?;
                let k = fields[2].parse()?;
                let raw = decode(fields[3])?.ok_or("missingraw")?;
                let hash = decode(fields[4])?
                    .ok_or("missinghash")?
                    .try_into()
                    .map_err(|_| "hashlen")?;
                let mut bytes = vec![0; size];
                match BloomGroup::new(
                    &mut bytes,
                    BlockType::TEST,
                    k,
                    Some(&raw),
                    0,
                    NativeEndian::native(),
                ) {
                    Err(gnunet_types::Error::Truncated) => "B 0".into(),
                    Err(e) => return Err(e.into()),
                    Ok(mut group) => {
                        let a = group.test_and_set(&hash);
                        let b = group.test_and_set(&hash);
                        let mut out = vec![0; size + 4];
                        match group.serialize_into(&mut out) {
                            Ok(Some(n)) => format!(
                                "B 1 {} {} 1 {} {}",
                                u8::from(a),
                                u8::from(b),
                                n,
                                hex(&out[..n])
                            ),
                            Err(gnunet_types::Error::NotReady) => {
                                format!("B 1 {} {} -1 0 -", u8::from(a), u8::from(b))
                            }
                            _ => return Err("bad serialize".into()),
                        }
                    }
                }
            }
            "L" => consumed_negative_merge()?,
            "J" => {
                let size1: usize = fields[1].parse()?;
                let k1 = fields[2].parse()?;
                let raw1 = decode(fields[3])?.ok_or("raw1")?;
                let size2: usize = fields[4].parse()?;
                let k2 = fields[5].parse()?;
                let raw2 = decode(fields[6])?.ok_or("raw2")?;
                let hash: Hash = decode(fields[7])?
                    .ok_or("hash")?
                    .try_into()
                    .map_err(|_| "hashlen")?;
                let mut bytes1 = vec![0; size1];
                let mut bytes2 = vec![0; size2];
                let mut a = BloomGroup::new(
                    &mut bytes1,
                    BlockType::TEST,
                    k1,
                    Some(&raw1),
                    0,
                    NativeEndian::native(),
                )?;
                let mut b = BloomGroup::new(
                    &mut bytes2,
                    BlockType::DNS,
                    k2,
                    Some(&raw2),
                    0,
                    NativeEndian::native(),
                )?;
                b.test_and_set(&hash);
                let result = match gnunet_block::group_merge(Some(&mut a), Some(b))? {
                    gnunet_block::MergeOutcome::Consumed(code) => code,
                    _ => return Err("unexpected merge".into()),
                };
                let duplicate = a.test_and_set(&hash);
                let mut out = vec![0; size1 + 4];
                let (code, n) = match a.serialize_into(&mut out) {
                    Ok(Some(n)) => (1, n),
                    Err(gnunet_types::Error::NotReady) => (-1, 0),
                    _ => return Err("serialize".into()),
                };
                format!(
                    "J {} {} {} {} {}",
                    result as i32,
                    u8::from(duplicate),
                    code,
                    n,
                    if n > 0 { hex(&out[..n]) } else { "-".into() }
                )
            }
            "G" => {
                let kind = BlockType(fields[1].parse()?);
                let mode: u32 = fields[2].parse()?;
                let size: u32 = fields[3].parse()?;
                let raw = decode(fields[4])?;
                let seen = decode(fields[5])?;
                let query: Hash = decode(fields[6])?
                    .ok_or("missingquery")?
                    .try_into()
                    .map_err(|_| "querylen")?;
                let xquery = decode(fields[7])?;
                let block = decode(fields[8])?.unwrap_or_default();
                let sizing = match mode {
                    0 => GroupSizing::SeenSet(size),
                    1 => GroupSizing::FilterBytes(size),
                    _ => GroupSizing::Fallback,
                };
                let mut storage = vec![0; 32768];
                let mut group =
                    match context.create_group(kind, sizing, raw.as_deref(), 0, &mut storage) {
                        Err(gnunet_types::Error::Truncated) => None,
                        result => result?,
                    };
                let hashes: Vec<Hash> = seen
                    .map(|v| v.try_into().map_err(|_| "seenlen"))
                    .transpose()?
                    .into_iter()
                    .collect();
                let marked = gnunet_block::group_set_seen(group.as_mut(), &hashes);
                let mut work = Work {
                    hello: &mut addresses,
                    hello_limits: gnunet_hello::Limits {
                        maximum_input_bytes: 65535,
                        maximum_address_bytes: 65535,
                        maximum_addresses: 1024,
                    },
                    hello_profile: profile,
                    pow: &mut memory,
                };
                let mut now = || utc;
                let first = context.check_reply(
                    kind,
                    group.as_mut(),
                    &query,
                    xquery.as_deref(),
                    &block,
                    &mut work,
                    &mut now,
                )?;
                let second = context.check_reply(
                    kind,
                    group.as_mut(),
                    &query,
                    xquery.as_deref(),
                    &block,
                    &mut work,
                    &mut now,
                )?;
                let mut out = vec![0; 32772];
                let (code, n) = match gnunet_block::group_serialize(group.as_ref(), &mut out) {
                    Ok(Some(n)) => (1, n),
                    Ok(None) => (0, 0),
                    Err(gnunet_types::Error::NotReady) => (-1, 0),
                    Err(e) => return Err(e.into()),
                };
                format!(
                    "G {} {} {} {} {} {} {}",
                    u8::from(group.is_some()),
                    marked as i32,
                    first as i32,
                    second as i32,
                    code,
                    n,
                    if n > 0 { hex(&out[..n]) } else { "-".into() }
                )
            }
            "D" => {
                let kind = BlockType(fields[2].parse()?);
                let query = decode(fields[3])?
                    .ok_or("missingquery")?
                    .try_into()
                    .map_err(|_| "querylen")?;
                let xquery = decode(fields[4])?;
                let block = decode(fields[5])?.unwrap_or_default();
                let mut work = Work {
                    hello: &mut addresses,
                    hello_limits: gnunet_hello::Limits {
                        maximum_input_bytes: 65535,
                        maximum_address_bytes: 65535,
                        maximum_addresses: 1024,
                    },
                    hello_profile: profile,
                    pow: &mut memory,
                };
                let mut now = || utc;
                let mut key = [0xa5; 64];
                let code = match fields[1] {
                    "Q" => context.check_query(kind, &query, xquery.as_deref().unwrap_or_default())
                        as i32,
                    "V" => context.check_block(kind, &block, &mut work, &mut now)? as i32,
                    "K" => {
                        let result = context.get_key(kind, &block, &mut work, &mut now)?;
                        if let Some(value) = result.key {
                            key = value;
                        }
                        result.status as i32
                    }
                    "R" => context.check_reply(
                        kind,
                        None,
                        &query,
                        xquery.as_deref(),
                        &block,
                        &mut work,
                        &mut now,
                    )? as i32,
                    _ => return Err("unknownoperation".into()),
                };
                format!(
                    "D {} {} {} {}",
                    fields[1],
                    kind.0,
                    code,
                    if fields[1] == "K" {
                        hex(&key)
                    } else {
                        "-".into()
                    }
                )
            }
            "N" => nullable()?,
            _ => return Err("unknown control".into()),
        };
        writeln!(stdout, "{output}")?;
        stdout.flush()?;
    }
    Ok(())
}
fn main() -> Result<(), Box<dyn Error>> {
    run()
}
