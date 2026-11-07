//! RFC3492 bounded Bootstring; native libidn2 basic-input restrictions are explicit.
use crate::{Error, native};
fn adapt(mut delta: u32, points: u32, first: bool) -> u32 {
    delta = if first { delta / 700 } else { delta / 2 };
    delta += delta / points;
    let mut k = 0;
    while delta > 455 {
        delta /= 35;
        k += 36;
    }
    k + 36 * delta / (delta + 38)
}
fn threshold(k: u32, bias: u32) -> u32 {
    if k <= bias {
        1
    } else if k >= bias + 26 {
        26
    } else {
        k - bias
    }
}
fn digit(c: u32) -> u32 {
    match c {
        97..=122 => c - 97,
        65..=90 => c - 65,
        48..=57 => c - 48 + 26,
        _ => 0,
    }
}
fn basic(c: u32) -> bool {
    matches!(c,97..=122|65..=90|48..=57|45|95)
}
pub(crate) fn decode(bytes: &[u8], out: &mut [u32]) -> Result<usize, Error> {
    decode_input(bytes.len(), |i| u32::from(bytes[i]), out)
}
pub(crate) fn decode_scalars(input: &[u32], out: &mut [u32]) -> Result<usize, Error> {
    decode_input(input.len(), |i| input[i], out)
}
fn decode_input(len: usize, get: impl Fn(usize) -> u32, out: &mut [u32]) -> Result<usize, Error> {
    if len == 0 || (0..len).any(|i| !basic(get(i))) {
        return Err(native(-202));
    }
    let mut used = 0;
    let mut pos = 0;
    if let Some(last) = (0..len).rfind(|i| get(*i) == 45) {
        if last == 0 || last + 1 == len {
            return Err(native(-202));
        }
        if last >= out.len() {
            return Err(native(-203));
        }
        for (i, dst) in out[..last].iter_mut().enumerate() {
            *dst = get(i);
        }
        used = last;
        pos = last + 1;
    }
    let mut n = 128u32;
    let mut i = 0u32;
    let mut bias = 72;
    while pos < len {
        let old = i;
        let mut w = 1u32;
        let mut k = 36u32;
        loop {
            if pos >= len {
                return Err(native(-202));
            }
            let cp = get(pos);
            pos += 1;
            let d = digit(cp);
            i = i
                .checked_add(d.checked_mul(w).ok_or(native(-204))?)
                .ok_or(native(-204))?;
            let t = threshold(k, bias);
            if d < t {
                break;
            }
            w = w.checked_mul(36 - t).ok_or(native(-204))?;
            k = k.checked_add(36).ok_or(native(-204))?;
        }
        let points = used as u32 + 1;
        bias = adapt(i - old, points, old == 0);
        n = n.checked_add(i / points).ok_or(native(-204))?;
        i %= points;
        if n > 0x10ffff || (0xd800..=0xdbff).contains(&n) {
            return Err(native(-202));
        }
        if used == out.len() {
            return Err(native(-203));
        }
        out.copy_within(i as usize..used, i as usize + 1);
        out[i as usize] = n;
        i += 1;
        used += 1;
    }
    Ok(used)
}
pub(crate) fn encode(input: &[u32], out: &mut [u8]) -> Result<usize, Error> {
    let mut used = 0;
    for cp in input {
        if *cp < 128 {
            put(out, &mut used, *cp as u8)?;
        }
    }
    let basic_count = used;
    let mut handled = used;
    if basic_count > 0 {
        put(out, &mut used, b'-')?;
    }
    let mut n = 128u32;
    let mut delta = 0u32;
    let mut bias = 72u32;
    while handled < input.len() {
        let m = input
            .iter()
            .copied()
            .filter(|c| *c >= n)
            .min()
            .ok_or(native(-202))?;
        delta = delta
            .checked_add(
                (m - n)
                    .checked_mul(handled as u32 + 1)
                    .ok_or(native(-204))?,
            )
            .ok_or(native(-204))?;
        n = m;
        for cp in input {
            if *cp < n {
                delta = delta.checked_add(1).ok_or(native(-204))?;
            }
            if *cp != n {
                continue;
            }
            let mut q = delta;
            let mut k = 36;
            loop {
                let t = threshold(k, bias);
                if q < t {
                    break;
                }
                emit(out, &mut used, t + (q - t) % (36 - t))?;
                q = (q - t) / (36 - t);
                k += 36;
            }
            emit(out, &mut used, q)?;
            bias = adapt(delta, handled as u32 + 1, handled == basic_count);
            delta = 0;
            handled += 1;
        }
        delta = delta.checked_add(1).ok_or(native(-204))?;
        n = n.checked_add(1).ok_or(native(-204))?;
    }
    Ok(used)
}
fn put(out: &mut [u8], used: &mut usize, c: u8) -> Result<(), Error> {
    let dst = out.get_mut(*used).ok_or(native(-203))?;
    *dst = c;
    *used += 1;
    Ok(())
}
fn emit(out: &mut [u8], used: &mut usize, d: u32) -> Result<(), Error> {
    put(
        out,
        used,
        if d < 26 {
            b'a' + d as u8
        } else {
            b'0' + (d - 26) as u8
        },
    )
}
