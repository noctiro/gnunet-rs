//! Actual native text-to-wire graph used by the external normal-C frontier tool.
#![forbid(unsafe_code)]
use gnunet_dns::{AbsoluteTime, Arena, Limits, NativeScratch, Packet, Query, Record};
use gnunet_idna::{Backend, Limits as ILimits, NativeProfile, Workspace};
use std::{
    error::Error,
    io::{self, Write},
};
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|v| format!("{v:02x}")).collect()
}
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = std::env::args().collect();
    let input = args.get(1).ok_or("missing hexadecimal packet")?;
    if !input.len().is_multiple_of(2) {
        return Err("odd hexadecimal input length".into());
    }
    let bytes: Vec<u8> = input
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| Ok(u8::from_str_radix(std::str::from_utf8(pair)?, 16)?))
        .collect::<Result<_, Box<dyn Error>>>()?;
    let maximum: u16 = args.get(2).ok_or("missing native capacity")?.parse()?;
    if !(12..=512).contains(&maximum) {
        return Err("capacity outside finite probe profile".into());
    }
    let mut names = [0; 16384];
    let mut arena = Arena::new(&mut names);
    let mut qs = [Query::EMPTY; 32];
    let mut rs = [Record::EMPTY; 32];
    let packet = Packet::parse(
        &bytes,
        AbsoluteTime::UNIX_EPOCH,
        &mut arena,
        &mut qs,
        &mut rs,
        Limits::DNS,
    )?;
    let mut idna = Workspace::new();
    let backend = Backend::new(
        &mut idna,
        ILimits::GNUNET,
        NativeProfile::Libunistring1_5Unicode18_0,
    );
    let mut work = [0; 4096];
    let mut text = [0; 4096];
    let mut scratch = NativeScratch::new(&mut work, &mut text, Limits::DNS);
    let mut target = [0; 16384];
    let mut arena = Arena::new(&mut target);
    let mut qs = [Query::EMPTY; 32];
    let mut rs = [Record::EMPTY; 32];
    let mut out = [0xa5; 512];
    let mut stdout = io::stdout().lock();
    match packet.pack_native(
        AbsoluteTime::UNIX_EPOCH,
        &backend,
        &mut scratch,
        &mut arena,
        &mut qs,
        &mut rs,
        &mut out[..usize::from(maximum)],
        maximum,
    ) {
        Ok(p) => writeln!(
            stdout,
            "{{\"truncated\":{},\"native_size\":{},\"queries\":{},\"answers\":{},\"authority\":{},\"additional\":{},\"wire\":\"{}\"}}",
            p.truncated,
            p.native_size
                .map(|s| s.to_string())
                .unwrap_or_else(|| "null".into()),
            p.counts.queries,
            p.counts.answers,
            p.counts.authority,
            p.counts.additional,
            hex(&out[..p.written])
        )?,
        Err(e) => {
            if !out.iter().all(|b| *b == 0xa5) {
                return Err("native pack changed output on error".into());
            }
            writeln!(stdout, "{{\"error\":\"{e:?}\"}}")?;
        }
    }
    Ok(())
}
