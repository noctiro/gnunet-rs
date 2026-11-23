//! Line-framed actual Rust conversion probe used by the normal-C differential runner.
#![expect(
    clippy::unwrap_used,
    reason = "The test and oracle require exact successful fixture parsing or fail immediately."
)]
#![expect(
    clippy::panic,
    reason = "An unknown operation must fail the reference probe instead of skipping it."
)]
#[expect(
    dead_code,
    reason = "The property oracle also reads the generated tables not used in each operation."
)]
#[path = "../src/tables.rs"]
mod tables;
use gnunet_idna::{Error, Limits, NativeProfile, Workspace, normalize_nfc, to_ascii, to_unicode};
use std::io::{self, BufRead, Write};
fn main() {
    let mut work = Workspace::new();
    let mut out = [0; 4064];
    let stdout = io::stdout();
    let mut stdout = io::BufWriter::new(stdout.lock());
    for line in io::stdin().lock().lines() {
        let line = line.unwrap();
        let (op, hex) = line.split_once('\t').unwrap();
        let bytes: Vec<u8> = hex
            .as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect();
        let result = match op {
            "A" => to_ascii(
                &bytes,
                &mut out,
                &mut work,
                Limits::GNUNET,
                NativeProfile::Libunistring1_5Unicode18_0,
            ),
            "U" => to_unicode(&bytes, &mut out, &mut work, Limits::GNUNET),
            "N" => normalize_nfc(
                &bytes,
                &mut out,
                &mut work,
                Limits::GNUNET,
                NativeProfile::Libunistring1_5Unicode18_0,
            ),
            "M" => normalize_nfc(
                &bytes,
                &mut out,
                &mut work,
                Limits::GNUNET,
                NativeProfile::Unicode15_1,
            ),
            "W" | "X" | "Y" => {
                let mut storage = [0; 1024];
                let mut arena = gnunet_dns::Arena::new(&mut storage);
                let backend = gnunet_idna::Backend::new(
                    &mut work,
                    Limits::GNUNET,
                    NativeProfile::Libunistring1_5Unicode18_0,
                );
                (|| -> Result<usize, gnunet_dns::Error> {
                    // X carries only a test-control offset before the actual
                    // DNS payload. It is never a production wire field.
                    let (payload, offset) = if op == "X" {
                        let fixed = bytes.get(..2).ok_or(gnunet_dns::Error::Truncated)?;
                        (
                            &bytes[2..],
                            usize::from(u16::from_be_bytes([fixed[0], fixed[1]])),
                        )
                    } else {
                        (bytes.as_slice(), 0)
                    };
                    let mut reader = gnunet_dns::Reader::at(
                        payload,
                        offset,
                        payload.len(),
                        gnunet_dns::Limits::DNS,
                    )?;
                    let name = if op == "Y" {
                        let record =
                            reader.record(gnunet_dns::AbsoluteTime::UNIX_EPOCH, &mut arena)?;
                        if record.kind != gnunet_dns::Type::CNAME {
                            return Err(gnunet_dns::Error::InvalidInput);
                        }
                        let gnunet_dns::RData::Hostname(name) = record.data else {
                            return Err(gnunet_dns::Error::InvalidInput);
                        };
                        name
                    } else {
                        reader.name(&mut arena)?
                    };
                    let prefix = format!("{}:", reader.position());
                    out[..prefix.len()].copy_from_slice(prefix.as_bytes());
                    let n =
                        name.write_native_text(&backend, &mut [0; 1024], &mut out[prefix.len()..])?;
                    Ok(prefix.len() + n)
                })()
                .map_err(|_| Error::Native(-1))
            }
            "F" => {
                let flags = gnunet_dns::Flags::from_bits_preserve(u16::from_be_bytes(
                    bytes.as_slice().try_into().unwrap(),
                ));
                let fields = format!(
                    "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
                    u8::from(flags.recursion_desired()),
                    u8::from(flags.message_truncated()),
                    u8::from(flags.authoritative_answer()),
                    flags.opcode(),
                    u8::from(flags.query_or_response()),
                    flags.return_code(),
                    u8::from(flags.checking_disabled()),
                    u8::from(flags.authenticated_data()),
                    u8::from(flags.reserved_zero()),
                    u8::from(flags.recursion_available())
                );
                // Round-trip all setters as well as accessors for every flag word.
                let rebuilt = gnunet_dns::Flags::default()
                    .with_recursion_desired(flags.recursion_desired())
                    .with_message_truncated(flags.message_truncated())
                    .with_authoritative_answer(flags.authoritative_answer())
                    .with_opcode(flags.opcode())
                    .unwrap()
                    .with_query_or_response(flags.query_or_response())
                    .with_return_code(flags.return_code())
                    .unwrap()
                    .with_checking_disabled(flags.checking_disabled())
                    .with_authenticated_data(flags.authenticated_data())
                    .with_reserved_zero(flags.reserved_zero())
                    .with_recursion_available(flags.recursion_available());
                assert_eq!(rebuilt.bits(), flags.bits());
                assert!(flags.with_opcode(16).is_err());
                assert!(flags.with_return_code(16).is_err());
                out[..fields.len()].copy_from_slice(fields.as_bytes());
                Ok(fields.len())
            }
            "G" => {
                use gnunet_dns::{class as c, opcode as o, return_code as r};
                let fields = [
                    c::INTERNET,
                    c::CHAOS,
                    c::HESIOD,
                    u16::from(o::QUERY),
                    u16::from(o::INVERSE_QUERY),
                    u16::from(o::STATUS),
                    u16::from(r::NO_ERROR),
                    u16::from(r::FORMAT_ERROR),
                    u16::from(r::SERVER_FAILURE),
                    u16::from(r::NAME_ERROR),
                    u16::from(r::NOT_IMPLEMENTED),
                    u16::from(r::REFUSED),
                    u16::from(r::YXDOMAIN),
                    u16::from(r::YXRRSET),
                    u16::from(r::NXRRSET),
                    u16::from(r::NOT_AUTH),
                    u16::from(r::NOT_ZONE),
                ]
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join("|");
                out[..fields.len()].copy_from_slice(fields.as_bytes());
                Ok(fields.len())
            }
            "H" => {
                let header = gnunet_dns::Header::decode(&bytes).unwrap();
                let mut encoded = [0xa5; 16];
                for cap in 0..12 {
                    assert_eq!(
                        header.encode(&mut encoded[..cap]),
                        Err(gnunet_dns::Error::Capacity)
                    );
                    assert_eq!(encoded, [0xa5; 16]);
                    assert_eq!(
                        gnunet_dns::Header::decode(&bytes[..cap]),
                        Err(gnunet_dns::Error::Truncated)
                    );
                }
                assert_eq!(header.encode(&mut encoded), Ok(12));
                assert_eq!(&encoded[..12], bytes);
                assert_eq!(&encoded[12..], &[0xa5; 4]);
                let fields = format!(
                    "{}|{}|{}|{}|{}|{}",
                    u16::from_be_bytes(header.id),
                    header.flags.bits(),
                    header.counts.queries,
                    header.counts.answers,
                    header.counts.authority,
                    header.counts.additional
                );
                out[..fields.len()].copy_from_slice(fields.as_bytes());
                Ok(fields.len())
            }
            "P" => {
                let c = core::str::from_utf8(&bytes)
                    .unwrap()
                    .chars()
                    .next()
                    .unwrap() as u32;
                let range = |table: &[(u32, u32, u8)]| {
                    let i = table.partition_point(|r| r.1 < c);
                    table.get(i).filter(|r| r.0 <= c).map_or(0, |r| r.2)
                };
                let bc = [
                    "L", "R", "AL", "EN", "AN", "NSM", "ES", "CS", "ET", "ON", "BN",
                ][usize::from(range(tables::BIDI18))];
                let jt = ["U", "L", "R", "D", "T", "C"][usize::from(range(tables::JOIN18))];
                let props = format!(
                    "{}|{}|{bc}|{jt}|{}",
                    range(tables::CCC18),
                    range(tables::MARK18),
                    range(tables::SCRIPT18)
                );
                out[..props.len()].copy_from_slice(props.as_bytes());
                Ok(props.len())
            }
            _ => panic!("unknown operation"),
        };
        match result {
            Ok(n) => {
                write!(stdout, "0\t").unwrap();
                for b in &out[..n] {
                    write!(stdout, "{b:02x}").unwrap();
                }
                writeln!(stdout).unwrap();
            }
            Err(e) => {
                let code = match e {
                    Error::Native(code) => code,
                    Error::Capacity => -10000,
                    Error::Resource => -10001,
                    Error::InteriorNul => -10002,
                };
                writeln!(stdout, "{code}\t").unwrap();
            }
        }
    }
}
