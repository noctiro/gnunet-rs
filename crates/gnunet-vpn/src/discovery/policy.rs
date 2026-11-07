//! Exit network/port sets expressed using the official REGEX grammar.
//! All valid rules contribute to the union, including zero-address networks.
//! No C-array sentinel or missing-prefix grouping defect is reproduced.
use super::EXIT_PREFIX;
use crate::{Address, Family};
use core::net::Ipv6Addr;
use gnunet_types::Error;

/// Largest expression fitting one official ANNOUNCE including its final NUL.
pub const MAX_EXPRESSION_BYTES: usize =
    gnunet_wire::official::MAX_MESSAGE_SIZE - gnunet_wire::official::regex::ANNOUNCE_PREFIX - 1;
const HEX: &[u8; 16] = b"0123456789ABCDEF";

/// Official port-set notation. Unspecified ports and the full positive1..65535
/// range include the port-zero control query. Negation starting at1 excludes0
/// too, matching the official converter's explicit normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ports {
    /// All query ports0..65535, including ICMP/control port zero.
    Any,
    /// A positive range, or its complement. Explicit endpoints must be1..65535.
    Range {
        /// Inclusive first configured port; zero is reserved for Any notation.
        first: u16,
        /// Inclusive last configured port.
        last: u16,
        /// True excludes this range, normalizing a first endpoint1 to0.
        negated: bool,
    },
}
#[derive(Clone, Copy)]
struct Intervals {
    values: [(u32, u32); 2],
    len: usize,
}
impl Ports {
    fn intervals(self) -> Result<Intervals, Error> {
        let mut out = Intervals {
            values: [(0, 0); 2],
            len: 0,
        };
        match self {
            Self::Any => {
                out.values[0] = (0, 65535);
                out.len = 1;
            }
            Self::Range {
                first,
                last,
                negated,
            } => {
                if first == 0 || first > last {
                    return Err(Error::InvalidInput);
                }
                if !negated {
                    out.values[0] = (
                        if first == 1 && last == 65535 {
                            0
                        } else {
                            u32::from(first)
                        },
                        u32::from(last),
                    );
                    out.len = 1;
                } else {
                    let first = if first == 1 { 0 } else { u32::from(first) };
                    if first > 0 {
                        out.values[0] = (0, first - 1);
                        out.len = 1;
                    }
                    if last < 65535 {
                        out.values[out.len] = (u32::from(last) + 1, 65535);
                        out.len += 1;
                    }
                }
            }
        }
        Ok(out)
    }
    /// Check explicit endpoint ordering and port-zero notation.
    pub fn validate(self) -> Result<(), Error> {
        self.intervals().map(|_| ())
    }
    /// Whether this valid set contains an actual query port.
    pub fn contains(self, port: u16) -> Result<bool, Error> {
        let ranges = self.intervals()?;
        Ok(ranges.values[..ranges.len]
            .iter()
            .any(|(first, last)| (*first..=*last).contains(&u32::from(port))))
    }
    /// Whether no valid VPN query port can match this set.
    pub fn is_empty(self) -> Result<bool, Error> {
        Ok(self.intervals()?.len == 0)
    }
}

/// One network/mask and port set. Address bits outside the mask are ignored.
/// This is announcement eligibility, not proof of native route reachability or
/// an authorization decision for the EXIT forwarding engine.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Rule {
    /// Network address, with no zero-address sentinel interpretation.
    pub network: Address,
    /// Same-family bit mask; arbitrary dotted masks remain exact bit sets.
    pub mask: Address,
    /// Query port set.
    pub ports: Ports,
}
impl Rule {
    /// Construct one CIDR rule, retaining the supplied address's original bits.
    pub fn prefix(network: Address, bits: u8, ports: Ports) -> Result<Self, Error> {
        if usize::from(bits) > network.len() * 8 {
            return Err(Error::InvalidInput);
        }
        let mask = match network {
            Address::V4(_) => {
                let mut mask = [0; 4];
                prefix_mask(bits, &mut mask);
                Address::V4(mask)
            }
            Address::V6(_) => {
                let mut mask = [0; 16];
                prefix_mask(bits, &mut mask);
                Address::V6(mask)
            }
        };
        let rule = Self {
            network,
            mask,
            ports,
        };
        rule.validate()?;
        Ok(rule)
    }
    /// Check mask family and the configured port-set shape.
    pub fn validate(self) -> Result<(), Error> {
        if self.network.family() != self.mask.family() {
            return Err(Error::InvalidInput);
        }
        self.ports.validate()
    }
    /// Test the represented destination set independently of expression layout.
    pub fn contains(self, address: Address, port: u16) -> Result<bool, Error> {
        self.validate()?;
        Ok(self.network.family() == address.family()
            && self
                .network
                .bytes()
                .iter()
                .zip(self.mask.bytes())
                .zip(address.bytes())
                .all(|((network, mask), address)| network & mask == address & mask)
            && self.ports.contains(port)?)
    }
}
fn prefix_mask(bits: u8, output: &mut [u8]) {
    for (i, byte) in output.iter_mut().enumerate() {
        let bits = usize::from(bits).saturating_sub(i * 8);
        *byte = if bits >= 8 {
            255
        } else if bits == 0 {
            0
        } else {
            255 << (8 - bits)
        };
    }
}
fn decimal(text: &str, limit: u32) -> Result<u32, Error> {
    if text.is_empty() {
        return Err(Error::InvalidInput);
    }
    let mut n = 0u32;
    for digit in text.bytes() {
        if !digit.is_ascii_digit() {
            return Err(Error::InvalidInput);
        }
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(u32::from(digit - b'0')))
            .ok_or(Error::InvalidInput)?;
        if n > limit {
            return Err(Error::InvalidInput);
        }
    }
    Ok(n)
}
fn ipv4(text: &str) -> Result<[u8; 4], Error> {
    let mut parts = text.split('.');
    let mut bytes = [0; 4];
    for byte in &mut bytes {
        *byte = decimal(parts.next().ok_or(Error::InvalidInput)?, 255)? as u8;
    }
    if parts.next().is_some() {
        return Err(Error::InvalidInput);
    }
    Ok(bytes)
}
fn ports(text: Option<&str>) -> Result<Ports, Error> {
    let Some(text) = text else {
        return Ok(Ports::Any);
    };
    let (negated, text) = text.strip_prefix('!').map_or((false, text), |s| (true, s));
    let (first, last) = text.split_once('-').unwrap_or((text, text));
    let ports = Ports::Range {
        first: decimal(first, 65535)? as u16,
        last: decimal(last, 65535)? as u16,
        negated,
    };
    ports.validate()?;
    Ok(ports)
}

/// Parse a single rule body, without its list semicolon. IPv4 accepts optional
/// CIDR or dotted mask and optional :[!]first[-last]. IPv6 requires /mask before
/// any port suffix; its address may use ordinary compressed or embedded-v4 form.
/// Decimal CIDR is the documented IPv6 mask. An explicit IPv6 mask followed by
/// :ports is also unambiguous and supported by the actual C parser.
/// No whitespace, signed unsigned-decimal input, interior NUL or trailing junk
/// is accepted. Unsafe scanf quirks and partial-policy acceptance are not copied.
pub fn parse_rule(family: Family, text: &str) -> Result<Rule, Error> {
    if text.is_empty()
        || text
            .bytes()
            .any(|b| b == 0 || b == b';' || b.is_ascii_whitespace())
    {
        return Err(Error::InvalidInput);
    }
    let rule = match family {
        Family::V4 => {
            let (address, port) = text
                .split_once(':')
                .map_or((text, None), |(a, p)| (a, Some(p)));
            let (address, mask) = address
                .split_once('/')
                .map_or((address, None), |(a, m)| (a, Some(m)));
            let network = Address::V4(ipv4(address)?);
            let ports = ports(port)?;
            if let Some(mask) = mask {
                if mask.contains('.') {
                    Rule {
                        network,
                        mask: Address::V4(ipv4(mask)?),
                        ports,
                    }
                } else {
                    Rule::prefix(network, decimal(mask, 32)? as u8, ports)?
                }
            } else {
                Rule::prefix(network, 32, ports)?
            }
        }
        Family::V6 => {
            let (address, suffix) = text
                .split_once('/')
                .map_or((text, None), |(a, s)| (a, Some(s)));
            let network = Address::V6(
                address
                    .parse::<Ipv6Addr>()
                    .map_err(|_| Error::InvalidInput)?
                    .octets(),
            );
            if let Some(suffix) = suffix {
                let (mask, port) = suffix
                    .rsplit_once(':')
                    .map_or((suffix, None), |(m, p)| (m, Some(p)));
                let ports = ports(port)?;
                if mask.contains(':') {
                    Rule {
                        network,
                        mask: Address::V6(
                            mask.parse::<Ipv6Addr>()
                                .map_err(|_| Error::InvalidInput)?
                                .octets(),
                        ),
                        ports,
                    }
                } else {
                    Rule::prefix(network, decimal(mask, 128)? as u8, ports)?
                }
            } else {
                Rule::prefix(network, 128, Ports::Any)?
            }
        }
    };
    rule.validate()?;
    Ok(rule)
}
fn check_text(text: &str) -> Result<(), Error> {
    if !text.is_empty()
        && (!text.ends_with(';') || text.bytes().any(|b| b == 0 || b.is_ascii_whitespace()))
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
fn parsed(family: Family, text: &str) -> impl Iterator<Item = Result<Rule, Error>> + Clone + '_ {
    text.split_terminator(';')
        .map(move |line| parse_rule(family, line))
}
fn validate_rules(
    rules: impl Iterator<Item = Result<Rule, Error>>,
) -> Result<(usize, usize), Error> {
    let mut family = None;
    let mut count = 0usize;
    let mut active = 0usize;
    for rule in rules {
        let rule = rule?;
        rule.validate()?;
        if family.is_some_and(|f| f != rule.network.family()) {
            return Err(Error::InvalidInput);
        }
        family = Some(rule.network.family());
        count = count.checked_add(1).ok_or(Error::Overflow)?;
        if !rule.ports.is_empty()? {
            active = active.checked_add(1).ok_or(Error::Overflow)?;
        }
    }
    Ok((count, active))
}

/// Parse all semicolon-terminated entries into caller storage. Empty text gives
/// zero rules. All entries are validated before capacity checks or output writes;
/// no zero-address sentinel is appended or interpreted. Capacity/error preserves
/// the destination, including any previous policy the caller still owns.
pub fn parse_into(family: Family, text: &str, output: &mut [Rule]) -> Result<usize, Error> {
    check_text(text)?;
    if text.is_empty() {
        return Ok(0);
    }
    let (count, _) = validate_rules(parsed(family, text))?;
    if output.len() < count {
        return Err(Error::Capacity);
    }
    for (slot, rule) in output.iter_mut().zip(parsed(family, text)) {
        *slot = rule?;
    }
    Ok(count)
}

struct Writer<'a> {
    output: Option<&'a mut [u8]>,
    offset: usize,
}
impl Writer<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self
            .offset
            .checked_add(bytes.len())
            .ok_or(Error::Overflow)?;
        if end > MAX_EXPRESSION_BYTES {
            return Err(Error::TooLarge);
        }
        if let Some(output) = self.output.as_mut() {
            output
                .get_mut(self.offset..end)
                .ok_or(Error::Capacity)?
                .copy_from_slice(bytes);
        }
        self.offset = end;
        Ok(())
    }
    fn byte(&mut self, byte: u8) -> Result<(), Error> {
        self.put(&[byte])
    }
}
fn choices(writer: &mut Writer<'_>, first: u8, last: u8) -> Result<(), Error> {
    if first != last {
        writer.byte(b'(')?;
    }
    for digit in first..=last {
        if digit != first {
            writer.byte(b'|')?;
        }
        writer.byte(HEX[usize::from(digit)])?;
    }
    if first != last {
        writer.byte(b')')?;
    }
    Ok(())
}
fn wildcard(writer: &mut Writer<'_>, digits: u8) -> Result<(), Error> {
    for _ in 0..digits {
        choices(writer, 0, 15)?;
    }
    Ok(())
}
fn interval(writer: &mut Writer<'_>, first: u32, last: u32, digits: u8) -> Result<(), Error> {
    let unit = 1u32 << (4 * (digits - 1));
    if first == 0 && last == unit * 16 - 1 {
        return wildcard(writer, digits);
    }
    let low = first / unit;
    let high = last / unit;
    if low == high {
        writer.byte(HEX[low as usize])?;
        if digits > 1 {
            interval(writer, first % unit, last % unit, digits - 1)?;
        }
        return Ok(());
    }
    let lower = !first.is_multiple_of(unit);
    let upper = last % unit != unit - 1;
    let full_first = low + u32::from(lower);
    let full_last = high - u32::from(upper);
    let full = full_first <= full_last;
    let branches = u8::from(lower) + u8::from(upper) + u8::from(full);
    if branches > 1 {
        writer.byte(b'(')?;
    }
    if lower {
        writer.byte(HEX[low as usize])?;
        interval(writer, first % unit, unit - 1, digits - 1)?;
    }
    if full {
        if lower {
            writer.byte(b'|')?;
        }
        choices(writer, full_first as u8, full_last as u8)?;
        wildcard(writer, digits - 1)?;
    }
    if upper {
        if lower || full {
            writer.byte(b'|')?;
        }
        writer.byte(HEX[high as usize])?;
        interval(writer, 0, last % unit, digits - 1)?;
    }
    if branches > 1 {
        writer.byte(b')')?;
    }
    Ok(())
}
fn emit_ports(writer: &mut Writer<'_>, ports: Ports) -> Result<(), Error> {
    let ranges = ports.intervals()?;
    if ranges.len > 1 {
        writer.byte(b'(')?;
    }
    for (i, (first, last)) in ranges.values[..ranges.len].iter().enumerate() {
        if i != 0 {
            writer.byte(b'|')?;
        }
        interval(writer, *first, *last, 4)?;
    }
    if ranges.len > 1 {
        writer.byte(b')')?;
    }
    Ok(())
}
fn masked_nibble(writer: &mut Writer<'_>, network: u8, mask: u8) -> Result<(), Error> {
    let multiple = mask != 15;
    if multiple {
        writer.byte(b'(')?;
    }
    let mut first = true;
    for digit in 0..=15 {
        if digit & mask == network & mask {
            if !first {
                writer.byte(b'|')?;
            }
            first = false;
            writer.byte(HEX[usize::from(digit)])?;
        }
    }
    if multiple {
        writer.byte(b')')?;
    }
    Ok(())
}
fn emit_rule(writer: &mut Writer<'_>, rule: Rule) -> Result<(), Error> {
    writer.put(match rule.network {
        Address::V4(_) => b"4-",
        Address::V6(_) => b"6-",
    })?;
    emit_ports(writer, rule.ports)?;
    writer.byte(b'-')?;
    for (network, mask) in rule.network.bytes().iter().zip(rule.mask.bytes()) {
        masked_nibble(writer, network >> 4, mask >> 4)?;
        masked_nibble(writer, network & 15, mask & 15)?;
    }
    Ok(())
}
fn emit_policy(
    rules: impl Iterator<Item = Result<Rule, Error>>,
    active: usize,
    exit: bool,
    writer: &mut Writer<'_>,
) -> Result<(), Error> {
    if exit {
        writer.put(EXIT_PREFIX)?;
    }
    if active > 1 {
        writer.byte(b'(')?;
    }
    let mut first = true;
    for rule in rules {
        let rule = rule?;
        if rule.ports.is_empty()? {
            continue;
        }
        if !first {
            writer.byte(b'|')?;
        }
        first = false;
        emit_rule(writer, rule)?;
    }
    if active > 1 {
        writer.byte(b')')?;
    }
    Ok(())
}
fn measure_iter<I>(rules: I, exit: bool) -> Result<Option<(usize, usize)>, Error>
where
    I: Iterator<Item = Result<Rule, Error>> + Clone,
{
    let (_, active) = validate_rules(rules.clone())?;
    if active == 0 {
        return Ok(None);
    }
    let mut count = Writer {
        output: None,
        offset: 0,
    };
    emit_policy(rules, active, exit, &mut count)?;
    Ok(Some((active, count.offset)))
}
fn render_iter<I>(rules: I, exit: bool, output: &mut [u8]) -> Result<Option<usize>, Error>
where
    I: Iterator<Item = Result<Rule, Error>> + Clone,
{
    let Some((active, size)) = measure_iter(rules.clone(), exit)? else {
        return Ok(None);
    };
    if output.len() < size {
        return Err(Error::Capacity);
    }
    let mut writer = Writer {
        output: Some(output),
        offset: 0,
    };
    emit_policy(rules, active, exit, &mut writer)?;
    Ok(Some(size))
}

/// Measure one full prefixed expression without allocating or writing output.
/// None denotes an empty matching set, including an empty rule slice.
pub fn rendered_exit_len(rules: &[Rule]) -> Result<Option<usize>, Error> {
    Ok(measure_iter(rules.iter().copied().map(Ok), true)?.map(|(_, size)| size))
}
/// Measure a full prefixed expression directly from validated policy text. This
/// lets a host reserve only the required output instead of the maximum frame.
pub fn compiled_exit_len(family: Family, text: &str) -> Result<Option<usize>, Error> {
    check_text(text)?;
    if text.is_empty() {
        return Ok(None);
    }
    Ok(measure_iter(parsed(family, text), true)?.map(|(_, size)| size))
}

/// Write a bare policy expression from an explicit same-family rule slice.
/// Every rule participates. None means no legal VPN query can match and writes
/// nothing. Output has no NUL; ANNOUNCE encoding adds it. A complete counting pass
/// precedes output, so invalid/capacity/oversize failures leave output unchanged.
pub fn render(rules: &[Rule], output: &mut [u8]) -> Result<Option<usize>, Error> {
    render_iter(rules.iter().copied().map(Ok), false, output)
}
/// Write a full official exit expression, with its application prefix bound to
/// the entire rule union. No result is advertised for an empty matching set.
pub fn render_exit(rules: &[Rule], output: &mut [u8]) -> Result<Option<usize>, Error> {
    render_iter(rules.iter().copied().map(Ok), true, output)
}
/// Parse documented semicolon-terminated IPv4/IPv6 policy text and write its bare
/// expression without allocating intermediate rules or strings. Empty text or
/// entirely excluded port sets give None. Original input remains caller-owned.
pub fn compile(family: Family, text: &str, output: &mut [u8]) -> Result<Option<usize>, Error> {
    check_text(text)?;
    if text.is_empty() {
        return Ok(None);
    }
    render_iter(parsed(family, text), false, output)
}
/// Parse and write the complete official prefixed exit announcement expression.
/// Correct grouping allows every configured rule to match normal VPN searches.
pub fn compile_exit(family: Family, text: &str, output: &mut [u8]) -> Result<Option<usize>, Error> {
    check_text(text)?;
    if text.is_empty() {
        return Ok(None);
    }
    render_iter(parsed(family, text), true, output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::exit_search;
    struct Matcher<'a> {
        expression: &'a [u8],
        word: &'a [u8],
        at: usize,
    }
    impl Matcher<'_> {
        fn union(&mut self, start: [bool; 64]) -> Result<[bool; 64], Error> {
            let mut result = self.sequence(start)?;
            while self.expression.get(self.at) == Some(&b'|') {
                self.at += 1;
                let branch = self.sequence(start)?;
                for (a, b) in result.iter_mut().zip(branch) {
                    *a |= b;
                }
            }
            Ok(result)
        }
        fn sequence(&mut self, mut states: [bool; 64]) -> Result<[bool; 64], Error> {
            while let Some(&byte) = self.expression.get(self.at) {
                if byte == b'|' || byte == b')' {
                    break;
                }
                self.at += 1;
                if byte == b'(' {
                    states = self.union(states)?;
                    if self.expression.get(self.at) != Some(&b')') {
                        return Err(Error::Malformed);
                    }
                    self.at += 1;
                } else {
                    let mut next = [false; 64];
                    for ((i, state), letter) in states.iter().enumerate().zip(self.word) {
                        if *state && byte == *letter {
                            next[i + 1] = true;
                        }
                    }
                    states = next;
                }
            }
            Ok(states)
        }
    }
    fn matches(expression: &[u8], address: Address, port: u16) -> Result<bool, Error> {
        let mut word = [0; 64];
        let size = exit_search(address, port, &mut word)?;
        let mut matcher = Matcher {
            expression,
            word: &word[..size],
            at: 0,
        };
        let mut start = [false; 64];
        start[0] = true;
        let result = matcher.union(start)?;
        if matcher.at != expression.len() {
            return Err(Error::Malformed);
        }
        Ok(result[size])
    }
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "One independent policy-language model asserts matching boundaries and unchanged buffers on refusal"
    )]
    fn documented_sets_radix_ranges_grouped_prefix_and_explicit_empty() -> Result<(), Error> {
        let mut output = [0; 4096];
        let n = compile(Family::V4, "192.1.2.0/24:80;", &mut output)?.ok_or(Error::Unavailable)?;
        assert_eq!(
            &output[..n],
            b"4-0050-C00102(0|1|2|3|4|5|6|7|8|9|A|B|C|D|E|F)(0|1|2|3|4|5|6|7|8|9|A|B|C|D|E|F)"
        );
        let n = compile_exit(Family::V4, "0.0.0.0/0:80;192.0.2.1:81;", &mut output)?
            .ok_or(Error::Unavailable)?;
        assert!(matches(&output[..n], Address::V4([203, 0, 113, 1]), 80)?);
        assert!(matches(&output[..n], Address::V4([192, 0, 2, 1]), 81)?);
        assert!(!matches(&output[..n], Address::V4([203, 0, 113, 1]), 81)?);
        let n = compile_exit(Family::V4, "192.0.2.1:80;198.51.100.1:443;", &mut output)?
            .ok_or(Error::Unavailable)?;
        assert!(matches(&output[..n], Address::V4([198, 51, 100, 1]), 443)?);
        let n = compile_exit(Family::V4, "192.1.0.0/8:!25-56;", &mut output)?
            .ok_or(Error::Unavailable)?;
        for port in [0, 1, 24, 25, 26, 56, 57, 65535] {
            assert_eq!(
                matches(&output[..n], Address::V4([192, 4, 5, 6]), port)?,
                !(25..=56).contains(&port)
            );
        }
        let n = compile_exit(Family::V4, "192.1.0.0/16:80-81;", &mut output)?
            .ok_or(Error::Unavailable)?;
        for port in [0, 1, 79, 80, 81, 82, 65535] {
            assert_eq!(
                matches(&output[..n], Address::V4([192, 1, 5, 6]), port)?,
                (80..=81).contains(&port)
            );
        }
        let n = compile_exit(Family::V6, "E1E1:ABCD::ABCD/126;", &mut output)?
            .ok_or(Error::Unavailable)?;
        for (address, wanted) in [
            ("E1E1:ABCD::ABCC", true),
            ("E1E1:ABCD::ABCF", true),
            ("E1E1:ABCD::ABD0", false),
        ] {
            let address = Address::V6(
                address
                    .parse::<Ipv6Addr>()
                    .map_err(|_| Error::InvalidInput)?
                    .octets(),
            );
            assert_eq!(matches(&output[..n], address, 49)?, wanted);
        }
        assert!(Ports::Any.contains(0)?);
        assert!(
            Ports::Range {
                first: 1,
                last: 65535,
                negated: false
            }
            .contains(0)?
        );
        assert!(
            !Ports::Range {
                first: 1,
                last: 25,
                negated: true
            }
            .contains(0)?
        );
        let mut unchanged = [0xa5; 16];
        assert_eq!(compile_exit(Family::V4, "", &mut unchanged)?, None);
        assert_eq!(
            compile_exit(Family::V4, "0.0.0.0/0:!1-65535;", &mut unchanged)?,
            None
        );
        assert_eq!(unchanged, [0xa5; 16]);
        assert!(compile_exit(Family::V4, "192.0.2.1:0;", &mut unchanged).is_err());
        assert!(compile_exit(Family::V4, "192.0.2.1", &mut unchanged).is_err());
        assert_eq!(
            compile_exit(Family::V4, "192.0.2.1:80;", &mut unchanged),
            Err(Error::Capacity)
        );
        assert_eq!(unchanged, [0xa5; 16]);
        let seed = Rule::prefix(Address::V4([1, 1, 1, 1]), 32, Ports::Any)?;
        let mut rules = [seed];
        assert_eq!(
            parse_into(Family::V4, "192.0.2.1;198.51.100.1;", &mut rules),
            Err(Error::Capacity)
        );
        assert_eq!(rules, [seed]);
        let rule = parse_rule(Family::V4, "198.1.4.5/255.0.255.0:80;");
        assert!(rule.is_err()); // parse_rule accepts one body, not list separators.
        assert!(
            parse_rule(Family::V4, "198.1.4.5/255.0.255.0:80")?
                .contains(Address::V4([198, 55, 4, 99]), 80)?
        );
        Ok(())
    }
}
