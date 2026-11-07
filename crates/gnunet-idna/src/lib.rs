//! Pure Rust, bounded Unicode 15.1 IDNA corresponding to GNUnet's libidn2
//! 2.3.8 ToASCII flags25 and ToUnicode flags16, with explicit runtime profiles.
//!
//! ToUnicode deliberately decodes without IDNA validation, as the native API
//! does. Native lookup checks ContextJ and recognizes ContextO rule identifiers;
//! it does not enforce ContextO conditions or the EN/AN prohibition. Explicit
//! strict label validation is provided separately and never changes lookup.
#![no_std]
#![forbid(unsafe_code)]
mod backend;
pub use backend::Backend;
mod normalize;
mod punycode;
#[rustfmt::skip]
mod tables;

/// Fixed native lookup table version.
pub const UNICODE_VERSION: &str = "15.1.0";
/// Fixed native implementation target.
pub const LIBIDN2_VERSION: &str = "2.3.8";
/// Native property/NFC dependency profile; lookup and mapping tables remain15.1.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeProfile {
    /// All properties and normalization fixed to Unicode15.1.
    Unicode15_1,
    /// Actual normal reference dependency libunistring1.5, using Unicode18.0.
    Libunistring1_5Unicode18_0,
}
/// Conversion failure. Native reason numbers are diagnostics, not a C ABI
/// compatibility contract; GNUnet callers receive one malformed-input result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The caller's output slice cannot hold the entire result.
    Capacity,
    /// The explicit input byte/work ceiling was exceeded.
    Resource,
    /// Input contains a NUL, outside the C-string input contract.
    InteriorNul,
    /// Native libidn2 status, for the deterministic conversion failures.
    Native(i32),
}
/// Caller-selected byte/work bound. Every accepted native domain is limited
/// separately by the libidn2 254-mapped-scalar pre-normalization bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum input bytes read, including ignored TR46 characters.
    pub maximum_input_bytes: usize,
}
impl Limits {
    /// Finite GNUnet native text input ceiling, matching the parser's maximum.
    pub const GNUNET: Self = Self {
        maximum_input_bytes: 65535,
    };
}
/// Explicit reusable scratch. No allocation or process Unicode state is used.
/// A mapped domain has at most254 scalars; canonical decomposition has at most
/// four scalars per input, so1016 is a complete NFC workspace bound.
pub struct Workspace {
    mapped: [u32; 254],
    normalized: [u32; 1016],
    label: [u32; 63],
    output: [u8; 1020],
}
impl Workspace {
    /// Create empty scratch; use static or caller-owned storage on small stacks.
    pub const fn new() -> Self {
        Self {
            mapped: [0; 254],
            normalized: [0; 1016],
            label: [0; 63],
            output: [0; 1020],
        }
    }
}
impl Default for Workspace {
    fn default() -> Self {
        Self::new()
    }
}

fn native(code: i32) -> Error {
    Error::Native(code)
}
fn input(bytes: &[u8], limits: Limits) -> Result<&str, Error> {
    if bytes.len() > limits.maximum_input_bytes {
        return Err(Error::Resource);
    }
    if bytes.contains(&0) {
        return Err(Error::InteriorNul);
    }
    core::str::from_utf8(bytes).map_err(|_| native(-200))
}
pub(crate) fn property(cp: u32, ranges: &[(u32, u32, u8)], fallback: u8) -> u8 {
    let i = ranges.partition_point(|r| r.1 < cp);
    ranges
        .get(i)
        .filter(|r| r.0 <= cp)
        .map_or(fallback, |r| r.2)
}
fn mapping(cp: u32) -> (u8, usize, usize) {
    let i = tables::MAPPING.partition_point(|r| r.1 < cp);
    tables::MAPPING
        .get(i)
        .filter(|r| r.0 <= cp)
        .map_or((4, 0, 0), |r| (r.2, usize::from(r.3), usize::from(r.4)))
}
fn tr_valid(cp: u32) -> bool {
    matches!(mapping(cp).0, 0 | 3 | 5 | 6)
}
fn mark(cp: u32, p: NativeProfile) -> bool {
    property(
        cp,
        if p == NativeProfile::Unicode15_1 {
            tables::MARK
        } else {
            tables::MARK18
        },
        0,
    ) != 0
}
fn ccc(cp: u32, p: NativeProfile) -> u8 {
    property(
        cp,
        if p == NativeProfile::Unicode15_1 {
            tables::CCC
        } else {
            tables::CCC18
        },
        0,
    )
}
fn validity(cp: u32) -> u8 {
    property(cp, tables::VALIDITY, 4)
}
fn bidi(cp: u32, p: NativeProfile) -> u8 {
    property(
        cp,
        if p == NativeProfile::Unicode15_1 {
            tables::BIDI
        } else {
            tables::BIDI18
        },
        0,
    )
}
fn joining(cp: u32, p: NativeProfile) -> u8 {
    property(
        cp,
        if p == NativeProfile::Unicode15_1 {
            tables::JOIN
        } else {
            tables::JOIN18
        },
        0,
    )
}
fn script(cp: u32, p: NativeProfile) -> u8 {
    property(
        cp,
        if p == NativeProfile::Unicode15_1 {
            tables::SCRIPT
        } else {
            tables::SCRIPT18
        },
        0,
    )
}
fn is_nfc(label: &[u32], scratch: &mut [u32], profile: NativeProfile) -> Result<bool, Error> {
    let n = normalize::nfc(label, scratch, profile)?;
    Ok(label == &scratch[..n])
}
fn structural(
    label: &[u32],
    scratch: &mut [u32],
    startend: bool,
    known_nfc: bool,
    profile: NativeProfile,
) -> Result<(), Error> {
    if !known_nfc && !is_nfc(label, scratch, profile)? {
        return Err(native(-300));
    }
    if label.len() >= 4 && label[2..4] == [45, 45] {
        return Err(native(-301));
    }
    if startend && (label.first() == Some(&45) || label.last() == Some(&45)) {
        return Err(native(-302));
    }
    if label.first().is_some_and(|c| mark(*c, profile)) {
        return Err(native(-303));
    }
    Ok(())
}
fn tr_check(
    label: &[u32],
    scratch: &mut [u32],
    known_nfc: bool,
    profile: NativeProfile,
) -> Result<(), Error> {
    structural(label, scratch, true, known_nfc, profile)?;
    if label.contains(&46) {
        return Err(native(-311));
    }
    if label.iter().any(|c| !tr_valid(*c)) {
        return Err(native(-313));
    }
    Ok(())
}
fn context_j(label: &[u32], profile: NativeProfile) -> Result<(), Error> {
    for (p, cp) in label.iter().copied().enumerate() {
        if validity(cp) != 1 {
            continue;
        }
        if p > 0 && ccc(label[p - 1], profile) == 9 {
            continue;
        }
        if cp == 0x200d || p == 0 || p + 1 == label.len() {
            return Err(native(-305));
        }
        if cp != 0x200c {
            return Err(native(-306));
        }
        let before = label[..p]
            .iter()
            .rev()
            .copied()
            .find(|c| joining(*c, profile) != 4);
        let after = label[p + 1..]
            .iter()
            .copied()
            .find(|c| joining(*c, profile) != 4);
        if !before.is_some_and(|c| matches!(joining(c, profile), 1 | 3))
            || !after.is_some_and(|c| matches!(joining(c, profile), 2 | 3))
        {
            return Err(native(-305));
        }
    }
    Ok(())
}
fn contexto_known(cp: u32) -> bool {
    matches!(cp,0xb7|0x375|0x5f3|0x5f4|0x660..=0x669|0x6f0..=0x6f9|0x30fb)
}
fn context_o(label: &[u32], profile: NativeProfile) -> Result<(), Error> {
    for (p, cp) in label.iter().copied().enumerate() {
        if validity(cp) != 2 {
            continue;
        }
        let ok = match cp {
            0xb7 => p > 0 && p + 1 < label.len() && label[p - 1] == 0x6c && label[p + 1] == 0x6c,
            0x375 => label.get(p + 1).is_some_and(|c| script(*c, profile) == 1),
            0x5f3 | 0x5f4 => p > 0 && script(label[p - 1], profile) == 2,
            0x660..=0x669 => !label.iter().any(|c| (0x6f0..=0x6f9).contains(c)),
            0x6f0..=0x6f9 => !label.iter().any(|c| (0x660..=0x669).contains(c)),
            0x30fb => label.iter().any(|c| matches!(script(*c, profile), 3..=5)),
            _ => return Err(native(-308)),
        };
        if !ok {
            return Err(native(-307));
        }
    }
    Ok(())
}
fn bidi_check(
    label: &[u32],
    strict: bool,
    force: bool,
    profile: NativeProfile,
) -> Result<(), Error> {
    if !force && !label.iter().any(|c| matches!(bidi(*c, profile), 1 | 2 | 4)) {
        return Ok(());
    }
    let Some(first) = label.first().map(|c| bidi(*c, profile)) else {
        return Ok(());
    };
    let rtl = matches!(first, 1 | 2);
    if !rtl && first != 0 {
        return Err(native(-310));
    }
    let mut endok = true;
    let mut en = false;
    let mut an = false;
    for c in &label[1..] {
        let b = bidi(*c, profile);
        en |= b == 3;
        an |= b == 4;
        if (rtl && matches!(b, 1..=5)) || (!rtl && matches!(b, 0 | 3 | 5)) {
            // libidn2 treats even NSM after punctuation as a valid ending.
            if b != 5 || !strict {
                endok = true;
            }
        } else {
            if !matches!(b, 6..=10) {
                return Err(native(-310));
            }
            endok = false;
        }
    }
    if !endok || (strict && rtl && en && an) {
        Err(native(-310))
    } else {
        Ok(())
    }
}
fn native_label_check(
    label: &[u32],
    scratch: &mut [u32],
    known_nfc: bool,
    profile: NativeProfile,
) -> Result<(), Error> {
    structural(label, scratch, false, known_nfc, profile)?;
    for cp in label {
        if validity(*cp) == 3 && !matches!(mapping(*cp).0, 5 | 6) {
            return Err(native(-304));
        }
    }
    context_j(label, profile)?;
    if label
        .iter()
        .any(|c| validity(*c) == 2 && !contexto_known(*c))
    {
        return Err(native(-308));
    }
    if label.iter().any(|c| validity(*c) == 4) {
        return Err(native(-309));
    }
    bidi_check(label, false, false, profile)?;
    if label.contains(&46) {
        return Err(native(-311));
    }
    if label.iter().any(|c| !tr_valid(*c)) {
        return Err(native(-313));
    }
    Ok(())
}
/// Validate an already NFC Unicode label with all RFC5892 ContextJ/ContextO
/// rules and RFC5893 Bidi constraints. This is explicitly stricter than GNUnet's
/// native lookup. `bidi_domain` applies Bidi rules to LTR labels in a domain that
/// contains any RTL label. No TR46 mapping or case conversion is performed.
pub fn validate_idna2008_label(
    label: &str,
    bidi_domain: bool,
    work: &mut Workspace,
) -> Result<(), Error> {
    let mut n = 0;
    for c in label.chars() {
        if n == work.label.len() {
            return Err(native(-206));
        }
        work.label[n] = u32::from(c);
        n += 1;
    }
    if n == 0 {
        return Err(native(-304));
    }
    let label = &work.label[..n];
    let profile = NativeProfile::Unicode15_1;
    structural(label, &mut work.normalized, true, false, profile)?;
    for cp in label {
        match validity(*cp) {
            3 => return Err(native(-304)),
            4 => return Err(native(-309)),
            _ => {}
        }
    }
    context_j(label, profile)?;
    context_o(label, profile)?;
    bidi_check(label, true, bidi_domain, profile)?;
    if label.iter().any(|c| *c >= 128) {
        punycode::encode(label, &mut work.output[..59])?;
    }
    Ok(())
}
/// Convert using GNUnet's exact nontransitional flags25 native lookup profile.
/// Errors leave output unchanged. No terminating NUL is written.
pub fn to_ascii(
    bytes: &[u8],
    out: &mut [u8],
    work: &mut Workspace,
    limits: Limits,
    profile: NativeProfile,
) -> Result<usize, Error> {
    let text = input(bytes, limits)?;
    let mut mapped = 0;
    for c in text.chars() {
        let cp = u32::from(c);
        let (status, start, len) = mapping(cp);
        if status == 4 {
            return Err(native(-304));
        }
        let seq: &[u32] = match status {
            1 => &[],
            2 | 6 => &tables::MAPCHARS[start..start + len],
            _ => core::slice::from_ref(&cp),
        };
        if mapped + seq.len() >= 255 {
            return Err(native(-205));
        }
        work.mapped[mapped..mapped + seq.len()].copy_from_slice(seq);
        mapped += seq.len();
    }
    let n = normalize::nfc(&work.mapped[..mapped], &mut work.normalized, profile)?;
    // The input mapped array is no longer needed and becomes NFC-check scratch.
    // A label accepted by native TR46 cannot need >254 normalization scalars.
    let mut err = None;
    let mut pos = 0;
    while pos < n {
        let end = work.normalized[pos..n]
            .iter()
            .position(|c| *c == 46)
            .map_or(n, |p| pos + p);
        let label = &work.normalized[pos..end];
        let check = if label.starts_with(&[120, 110, 45, 45]) {
            let len = punycode::decode_scalars(&label[4..], &mut work.label)?;
            tr_check(&work.label[..len], &mut work.mapped, false, profile)
        } else {
            tr_check(label, &mut work.mapped, true, profile)
        };
        if let Err(e) = check {
            err = Some(e);
        }
        pos = end + 1;
    }
    if let Some(e) = err {
        return Err(e);
    }
    let mut written = 0;
    pos = 0;
    loop {
        let end = work.normalized[pos..n]
            .iter()
            .position(|c| *c == 46)
            .map_or(n, |p| pos + p);
        let source = &work.normalized[pos..end];
        let ascii = source.iter().all(|c| *c < 128);
        let alabel = ascii && source.starts_with(&[120, 110, 45, 45]);
        let count;
        if ascii && !alabel {
            if source.len() > 63 {
                return Err(native(-206));
            }
            count = source.len();
            for (dst, cp) in work.output[written..written + count].iter_mut().zip(source) {
                *dst = *cp as u8;
            }
        } else {
            let label = if alabel {
                let len = punycode::decode_scalars(&source[4..], &mut work.label)?;
                &work.label[..len]
            } else {
                source
            };
            native_label_check(label, &mut work.mapped, !alabel, profile)?;
            work.output[written..written + 4].copy_from_slice(b"xn--");
            count = 4 + punycode::encode(label, &mut work.output[written + 4..written + 63])?;
            if alabel
                && (source.len() != count
                    || source
                        .iter()
                        .zip(&work.output[written..written + count])
                        .any(|(a, b)| *a != u32::from(*b)))
            {
                return Err(native(-314));
            }
            if !alabel {
                let decoded =
                    punycode::decode(&work.output[written + 4..written + count], &mut work.label)
                        .map_err(|_| native(-314))?;
                if source != &work.label[..decoded] {
                    return Err(native(-314));
                }
            }
        }
        if written + count > 255 - if count == 0 && end == n { 1 } else { 2 } {
            return Err(native(-205));
        }
        written += count;
        if end == n {
            break;
        }
        work.output[written] = b'.';
        written += 1;
        pos = end + 1;
    }
    if written > out.len() {
        return Err(Error::Capacity);
    }
    out[..written].copy_from_slice(&work.output[..written]);
    Ok(written)
}
/// Convert using GNUnet's flags16 ToUnicode profile: Punycode/UTF8 decoding,
/// case-preserving plain labels and no IDNA validation or NFC normalization.
/// Errors leave output unchanged. No terminating NUL is written.
pub fn to_unicode(
    bytes: &[u8],
    out: &mut [u8],
    work: &mut Workspace,
    limits: Limits,
) -> Result<usize, Error> {
    let text = input(bytes, limits)?;
    let mut written = 0;
    let mut total = 0;
    for (i, s) in text.split('.').enumerate() {
        if i != 0 {
            work.output[written] = b'.';
            written += 1;
            total += 1;
        }
        let alabel = s
            .as_bytes()
            .get(..4)
            .is_some_and(|b| b.eq_ignore_ascii_case(b"xn--"));
        let n = if alabel {
            punycode::decode(s.as_bytes().get(4..).ok_or(native(-202))?, &mut work.label)?
        } else {
            let mut n = 0;
            for c in s.chars() {
                if n == 63 {
                    return Err(native(-206));
                }
                work.label[n] = u32::from(c);
                n += 1;
            }
            n
        };
        if total + n > 255 {
            return Err(native(-205));
        }
        total += n;
        for cp in &work.label[..n] {
            let c = char::from_u32(*cp).ok_or(native(-200))?;
            let mut utf8 = [0; 4];
            let b = c.encode_utf8(&mut utf8).as_bytes();
            work.output[written..written + b.len()].copy_from_slice(b);
            written += b.len();
        }
    }
    if written > out.len() {
        return Err(Error::Capacity);
    }
    out[..written].copy_from_slice(&work.output[..written]);
    Ok(written)
}
/// Normalize at most254 input scalars using the explicit fixed NFC profile.
/// Canonical expansion needs at most1016 scalars or4064 UTF8 output bytes.
/// The caller output ceiling is checked before committing; errors preserve output.
pub fn normalize_nfc(
    bytes: &[u8],
    out: &mut [u8],
    work: &mut Workspace,
    limits: Limits,
    profile: NativeProfile,
) -> Result<usize, Error> {
    let text = input(bytes, limits)?;
    let mut n = 0;
    for c in text.chars() {
        if n == 254 {
            return Err(Error::Resource);
        }
        work.mapped[n] = u32::from(c);
        n += 1;
    }
    let n = normalize::nfc(&work.mapped[..n], &mut work.normalized, profile)?;
    let mut required = 0;
    for cp in &work.normalized[..n] {
        let c = char::from_u32(*cp).ok_or(native(-200))?;
        required += c.len_utf8();
    }
    if required > out.len() {
        return Err(Error::Capacity);
    }
    let mut written = 0;
    for cp in &work.normalized[..n] {
        // The same immutable scalars were checked before committing any byte.
        // The safe fallback is unreachable after the preflight above.
        let c = char::from_u32(*cp).unwrap_or(char::REPLACEMENT_CHARACTER);
        let mut b = [0; 4];
        let encoded = c.encode_utf8(&mut b).as_bytes();
        out[written..written + encoded.len()].copy_from_slice(encoded);
        written += encoded.len();
    }
    Ok(written)
}

/// Generic canonical NFD on valid Unicode scalars using the selected fixed
/// normalization profile. No IDNA mapping or 254-scalar label limit is applied.
/// Both output and ordering scratch are explicitly bounded by their caller;
/// output is scratch and may contain a partial decomposition after failure.
/// Invalid input scalars are rejected before writing either scratch buffer.
pub fn normalize_nfd_scalars(
    input: &[u32],
    output: &mut [u32],
    ordering: &mut [u32],
    profile: NativeProfile,
) -> Result<usize, Error> {
    if input.iter().any(|cp| char::from_u32(*cp).is_none()) {
        return Err(Error::Native(-200));
    }
    normalize::nfd(input, output, ordering, profile)
}

/// Generic canonical NFC on valid Unicode scalars with explicit output/order
/// scratch. There is no IDNA mapping or254-scalar label ceiling. Invalid input
/// scalars are rejected before output changes; capacity failure may leave a
/// partial canonical decomposition in scratch/output, never a successful value.
pub fn normalize_nfc_scalars(
    input: &[u32],
    output: &mut [u32],
    ordering: &mut [u32],
    profile: NativeProfile,
) -> Result<usize, Error> {
    if input.iter().any(|cp| char::from_u32(*cp).is_none()) {
        return Err(Error::Native(-200));
    }
    normalize::nfc_bounded(input, output, ordering, profile)
}
