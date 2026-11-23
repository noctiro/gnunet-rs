//! The packed libnv subset required by FreeBSD 14.5 and 15.0 `pf_killstates_nv`.
use std::{
    ffi::CStr,
    io,
    num::{NonZeroU32, NonZeroU64},
};

const CAPACITY: usize = 2048;
const HEADER: usize = 19;
const PAIR: usize = 19;
const NUMBER: u8 = 3;
const LIST: u8 = 5;

pub(super) fn invalid() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "malformed FreeBSD PF nvlist")
}

struct Builder {
    bytes: [u8; CAPACITY],
    len: usize,
    headers: [usize; 10],
    header_count: usize,
}

impl Builder {
    fn push(&mut self, bytes: &[u8]) -> io::Result<()> {
        let end = self.len.checked_add(bytes.len()).ok_or_else(invalid)?;
        self.bytes
            .get_mut(self.len..end)
            .ok_or_else(invalid)?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    fn header(&mut self) -> io::Result<()> {
        *self
            .headers
            .get_mut(self.header_count)
            .ok_or_else(invalid)? = self.len;
        self.header_count += 1;
        let mut header = [0; HEADER];
        header[0] = 0x6c;
        self.push(&header)
    }

    fn pair(&mut self, kind: u8, name: &CStr, size: usize, items: u64) -> io::Result<()> {
        let name = name.to_bytes_with_nul();
        let mut header = [0; PAIR];
        header[0] = kind;
        let name_len = u16::try_from(name.len()).map_err(io::Error::other)?;
        header[1..3].copy_from_slice(&name_len.to_le_bytes());
        header[3..11].copy_from_slice(&(size as u64).to_le_bytes());
        header[11..].copy_from_slice(&items.to_le_bytes());
        self.push(&header)?;
        self.push(name)
    }

    fn field(&mut self, kind: u8, name: &CStr, payload: &[u8], items: u64) -> io::Result<()> {
        self.pair(kind, name, payload.len(), items)?;
        self.push(payload)
    }

    fn number(&mut self, name: &CStr, value: u64) -> io::Result<()> {
        self.field(NUMBER, name, &value.to_le_bytes(), 0)
    }

    fn list(
        &mut self,
        name: &CStr,
        fill: impl FnOnce(&mut Self) -> io::Result<()>,
    ) -> io::Result<()> {
        let extent_at = self.len + 3;
        self.pair(LIST, name, 0, 0)?;
        let start = self.len;
        self.header()?;
        fill(self)?;
        // A child pair's data length is the standalone list size. Its UP
        // marker belongs to the enclosing list. The child header itself uses
        // the remaining size of the whole packed buffer, just like libnv.
        let size = (self.len - start) as u64;
        self.bytes[extent_at..extent_at + 8].copy_from_slice(&size.to_le_bytes());
        self.pair(255, c"", 0, 0)
    }

    fn rule_address(&mut self, side: &CStr) -> io::Result<()> {
        self.list(side, |rule| {
            rule.list(c"addr", |wrap| {
                wrap.number(c"type", 0)?; // PF_ADDR_ADDRMASK
                wrap.number(c"iflags", 0)?;
                for name in [c"addr", c"mask"] {
                    wrap.list(name, |address| address.field(7, c"addr", &[0; 16], 0))?;
                }
                Ok(())
            })?;
            rule.field(9, c"port", &[0; 16], 2)?;
            rule.number(c"neg", 0)?;
            rule.number(c"port_op", 0)
        })
    }

    fn finish(mut self) -> ([u8; CAPACITY], usize) {
        for &start in &self.headers[..self.header_count] {
            let rest = (self.len - start - HEADER) as u64;
            self.bytes[start + 11..start + HEADER].copy_from_slice(&rest.to_le_bytes());
        }
        (self.bytes, self.len)
    }
}

pub(super) fn kill(state: NonZeroU64, creator: NonZeroU32) -> io::Result<([u8; CAPACITY], usize)> {
    let mut request = Builder {
        bytes: [0; CAPACITY],
        len: 0,
        headers: [0; 10],
        header_count: 0,
    };
    request.header()?;
    request.list(c"cmp", |cmp| {
        // pfctl prints the native state ID and converts the creator from
        // network order. Its request converts only the creator back.
        cmp.number(c"id", state.get())?;
        cmp.number(c"creatorid", u64::from(creator.get().to_be()))?;
        cmp.number(c"direction", 0)
    })?;
    request.number(c"af", 0)?;
    request.number(c"proto", 0)?;
    request.rule_address(c"src")?;
    request.rule_address(c"dst")?;
    request.field(4, c"ifname", b"\0", 0)?;
    request.field(4, c"label", b"\0", 0)?;
    request.field(2, c"kill_match", &[0], 0)?;
    Ok(request.finish())
}

pub(super) fn ack(bytes: &[u8]) -> io::Result<bool> {
    const NAME: &[u8] = b"killed\0";
    if bytes.len() != HEADER + PAIR + NAME.len() + 8
        || bytes[..2] != [0x6c, 0]
        || !matches!(bytes[2], 0 | 0x80)
        || bytes[3..11] != [0; 8]
        || bytes[HEADER] != NUMBER
        || bytes[HEADER + 11..HEADER + PAIR] != [0; 8]
        || &bytes[HEADER + PAIR..HEADER + PAIR + NAME.len()] != NAME
    {
        return Err(invalid());
    }
    let big_endian = bytes[2] == 0x80;
    let read = |field: &[u8]| -> io::Result<u64> {
        let field = field.try_into().map_err(|_| invalid())?;
        Ok(if big_endian {
            u64::from_be_bytes(field)
        } else {
            u64::from_le_bytes(field)
        })
    };
    let name_size = if big_endian { [0, 7] } else { [7, 0] };
    if bytes[HEADER + 1..HEADER + 3] != name_size
        || read(&bytes[11..HEADER])? != (bytes.len() - HEADER) as u64
        || read(&bytes[HEADER + 3..HEADER + 11])? != 8
    {
        return Err(invalid());
    }
    match read(&bytes[HEADER + PAIR + NAME.len()..])? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_native_identity_and_nested_extents() -> io::Result<()> {
        let state = NonZeroU64::new(0x1122_3344_5566_7788).ok_or_else(invalid)?;
        let creator = NonZeroU32::new(0xaabb_ccdd).ok_or_else(invalid)?;
        let (request, len) = kill(state, creator)?;
        let read = |range: std::ops::Range<usize>| -> io::Result<u64> {
            Ok(u64::from_le_bytes(
                request[range].try_into().map_err(|_| invalid())?,
            ))
        };
        if request[0] != 0x6c
            || read(11..19)? != (len - 19) as u64
            || read(22..30)? != 123
            || &request[38..42] != b"cmp\0"
            || request[42] != 0x6c
            || read(53..61)? != (len - 61) as u64
            || &request[80..83] != b"id\0"
            || read(83..91)? != state.get()
            || &request[110..120] != b"creatorid\0"
            || read(120..128)? != u64::from(creator.get().to_be())
        {
            return Err(io::Error::other(
                "PF state mutation changed the original ID or nvlist layout",
            ));
        }
        Ok(())
    }

    #[test]
    fn exact_ack_refuses_wider_results() -> io::Result<()> {
        let mut reply = [0; 53];
        reply[0] = 0x6c;
        reply[11] = 34;
        reply[19] = 3;
        reply[20] = 7;
        reply[22] = 8;
        reply[38..45].copy_from_slice(b"killed\0");
        if ack(&reply)? {
            return Err(io::Error::other("PF missing state was counted as retired"));
        }
        reply[45] = 1;
        if !ack(&reply)? {
            return Err(io::Error::other("PF exact retirement receipt was lost"));
        }
        reply[45] = 2;
        if ack(&reply).is_ok() {
            return Err(io::Error::other(
                "PF multiple-state retirement was accepted as exact",
            ));
        }
        Ok(())
    }
}
