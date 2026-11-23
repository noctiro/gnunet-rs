//! Read the peer's generated hexadecimal address-prefix policy.
use crate::Failure;
use gnunet_config::Configuration;
use gnunet_native::filesystem::Directory;
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read},
    num::NonZeroU32,
    time::Duration,
};

const SECTION: &[u8] = b"regexprofiler";
const HEX: &[u8] = b"0123456789abcdef";
const SUFFIX: &[u8] = b"(0|1|2|3|4|5|6|7|8|9|a|b|c|d|e|f)*";
const MAX_FILE_BYTES: usize = 1024 * 1024;
const MAX_PREFIXES: usize = 65536;
const MAX_ADDRESS_DIGITS: usize = 32;

pub(crate) struct Policy {
    pub(crate) expression: Vec<u8>,
    pub(crate) compression: u16,
    pub(crate) maximum_delay: NonZeroU32,
}

fn invalid(reason: &'static str) -> Failure {
    io::Error::new(io::ErrorKind::InvalidData, reason).into()
}

impl Policy {
    pub(super) fn read(config: &Configuration, maximum_expression: usize) -> Result<Self, Failure> {
        let directory = Directory::open_source(&config.get_path("regexprofiler", "POLICY_DIR")?)?;
        let index = usize::try_from(config.get_number(b"testbed", b"PEERID")?)?;
        let entry = directory
            .entries()?
            .enumerate()
            .find_map(|(offset, entry)| match entry {
                Err(error) => Some(Err(error)),
                Ok(name) if offset == index => Some(Ok(name)),
                Ok(_) => None,
            })
            .ok_or_else(|| invalid("TESTBED PEERID has no entry in REGEXPROFILER POLICY_DIR"))??;
        let compression = u16::try_from(config.get_number(SECTION, b"MAX_PATH_COMPRESSION")?)?;
        let maximum_delay = if config.get(SECTION, b"REANNOUNCE_PERIOD_MAX").is_some() {
            config.get_time(SECTION, b"REANNOUNCE_PERIOD_MAX")?
        } else {
            600_000_000
        };
        let maximum_delay = u32::try_from(maximum_delay)
            .ok()
            .and_then(NonZeroU32::new)
            .ok_or_else(|| {
                invalid("REGEXPROFILER REANNOUNCE_PERIOD_MAX requires 1..=4294967295 microseconds")
            })?;
        let prefix = config
            .get(SECTION, b"REGEX_PREFIX")
            .ok_or_else(|| invalid("REGEXPROFILER REGEX_PREFIX is required"))?;
        let file = read_file(directory.open_file(&entry)?)?;
        Ok(Self {
            expression: compose(prefix, &file, maximum_expression)?,
            compression,
            maximum_delay,
        })
    }
}

fn read_file(file: File) -> Result<Vec<u8>, Failure> {
    let mut buffer = Vec::new();
    file.take((MAX_FILE_BYTES + 1) as u64)
        .read_to_end(&mut buffer)?;
    if buffer.len() > MAX_FILE_BYTES {
        return Err(invalid("REGEXPROFILER policy exceeds the input limit"));
    }
    Ok(buffer)
}

/// Uniform delay in the official half-open interval. Exclude the uneven
/// tail of the system random range before taking the remainder.
pub(super) fn random_delay(maximum: NonZeroU32) -> Result<Duration, Failure> {
    let maximum = u64::from(maximum.get());
    let limit = (1_u64 << 32) / maximum * maximum;
    loop {
        let value =
            u64::from(getrandom::u32().map_err(|error| io::Error::other(error.to_string()))?);
        if value < limit {
            return Ok(Duration::from_micros(value % maximum));
        }
    }
}

fn read_prefixes(input: &[u8]) -> Result<BTreeSet<Vec<u8>>, Failure> {
    let mut prefixes = BTreeSet::new();
    for row in input
        .split(u8::is_ascii_whitespace)
        .filter(|row| !row.is_empty())
    {
        let literal = row
            .iter()
            .take_while(|byte| byte.is_ascii_hexdigit())
            .count();
        if row.len() == literal {
            insert(&mut prefixes, row, None)?;
            continue;
        }
        let choices = row[literal..]
            .strip_prefix(b"(")
            .and_then(|group| group.strip_suffix(b")"))
            .ok_or_else(|| {
                invalid("expected hexadecimal policy prefix and optional final digit choices")
            })?;
        let mut seen = [false; 16];
        for choice in choices.split(|byte| *byte == b'|') {
            let [byte] = choice else {
                return Err(invalid("each hexadecimal policy choice must be one digit"));
            };
            let digit = HEX
                .iter()
                .position(|digit| *digit == byte.to_ascii_lowercase())
                .ok_or_else(|| invalid("invalid hexadecimal policy digit"))?;
            if std::mem::replace(&mut seen[digit], true) {
                return Err(invalid("duplicate hexadecimal policy digit"));
            }
            insert(&mut prefixes, &row[..literal], Some(*byte))?;
        }
        // The trailing hexadecimal Kleene star covers a complete lowercase
        // digit choice as well as the zero-digit endpoint used by the profiler.
        if seen.iter().all(|digit| *digit) && choices.iter().all(|byte| !byte.is_ascii_uppercase())
        {
            insert(&mut prefixes, &row[..literal], None)?;
        }
    }
    if prefixes.is_empty() {
        return Err(invalid("REGEXPROFILER policy contains no address prefixes"));
    }
    Ok(prefixes)
}

fn insert(
    prefixes: &mut BTreeSet<Vec<u8>>,
    literal: &[u8],
    digit: Option<u8>,
) -> Result<(), Failure> {
    if literal.len() + usize::from(digit.is_some()) > MAX_ADDRESS_DIGITS
        || prefixes.len() == MAX_PREFIXES
    {
        return Err(invalid("REGEXPROFILER address prefix capacity exceeded"));
    }
    let mut prefix = literal.to_vec();
    prefix.extend(digit);
    prefixes.insert(prefix);
    Ok(())
}

struct Expression {
    bytes: Vec<u8>,
    maximum: usize,
}

impl Expression {
    fn extend(&mut self, bytes: &[u8]) -> Result<(), Failure> {
        if bytes.len() > self.maximum - self.bytes.len() {
            return Err(invalid(
                "REGEXPROFILER composed expression exceeds the compiler limit",
            ));
        }
        self.bytes.try_reserve(bytes.len())?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Factor literal prefixes in lexical order. Each nested call consumes at
    /// least one digit, so the address width also bounds the traversal stack.
    fn address(&mut self, prefixes: &[Vec<u8>], offset: usize) -> Result<(), Failure> {
        let optional = prefixes[0].len() == offset;
        let tails = &prefixes[usize::from(optional)..];
        if tails.is_empty() {
            return Ok(());
        }
        let grouped = optional || tails[0][offset] != tails[tails.len() - 1][offset];
        if grouped {
            self.extend(b"(")?;
        }
        for (index, same) in tails
            .chunk_by(|left, right| left[offset] == right[offset])
            .enumerate()
        {
            if index > 0 {
                self.extend(b"|")?;
            }
            let first = &same[0];
            let last = &same[same.len() - 1];
            let common = first[offset..]
                .iter()
                .zip(&last[offset..])
                .take_while(|(left, right)| left == right)
                .count();
            self.extend(&first[offset..offset + common])?;
            self.address(same, offset + common)?;
        }
        if grouped {
            self.extend(if optional { b")?" } else { b")" })?;
        }
        Ok(())
    }
}

fn compose(prefix: &[u8], input: &[u8], maximum: usize) -> Result<Vec<u8>, Failure> {
    let mut prefixes = Vec::new();
    // A lowercase hexadecimal suffix beneath a retained prefix is already
    // covered by the final star. Retain uppercase suffixes as separate paths.
    for candidate in read_prefixes(input)? {
        if (0..candidate.len()).any(|length| {
            candidate[length..].iter().all(|byte| HEX.contains(byte))
                && prefixes
                    .binary_search_by(|entry: &Vec<u8>| entry.as_slice().cmp(&candidate[..length]))
                    .is_ok()
        }) {
            continue;
        }
        prefixes.push(candidate);
    }
    let mut expression = Expression {
        bytes: Vec::new(),
        maximum,
    };
    expression.extend(prefix)?;
    expression.address(&prefixes, 0)?;
    expression.extend(SUFFIX)?;
    Ok(expression.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Compare composed official policy bytes"
    )]
    fn composes_only_the_hexadecimal_prefix_language() -> Result<(), Failure> {
        let expected = [b"GNVPN(10(0|1)|20F)".as_slice(), SUFFIX].concat();
        assert_eq!(
            compose(b"GNVPN", b"100\n101\n20(F)\n100f\n", 128)?,
            expected
        );
        assert_eq!(
            compose(b"GNVPN", b"a(0|1|2|3|4|5|6|7|8|9|a|b|c|d|e|f)\n ab", 128)?,
            [b"GNVPNa".as_slice(), SUFFIX].concat()
        );
        assert!(compose(b"GNVPN", b"10+", 128).is_err());
        assert!(compose(b"GNVPN", b"100\n101", 6).is_err());
        Ok(())
    }
}
