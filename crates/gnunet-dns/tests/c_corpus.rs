//! Existing actual normal-C corpus, with explicit pending and correction rows.
#![expect(
    clippy::unwrap_used,
    reason = "Tests require successful prerequisite construction and exact independent reference fixtures."
)]
#![expect(
    clippy::panic,
    reason = "An unknown oracle fixture/action must fail the test instead of being ignored."
)]
use gnunet_dns::*;
const NOW: AbsoluteTime = AbsoluteTime::from_micros(100_000_000);
fn unhex(s: &str) -> Vec<u8> {
    assert_eq!(s.len() % 2, 0);
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
fn name(n: Name<'_>) -> String {
    let mut b = [0; 255];
    let size = n.write_dotted(&mut b).unwrap();
    hex(&b[..size])
}
fn query(q: Query<'_>) -> String {
    format!("{}/{}/{}", name(q.name), q.kind.0, q.class)
}
fn data(d: RData<'_>) -> String {
    match d {
        RData::Raw(b) => format!("raw:{}", hex(b)),
        RData::Hostname(n) => format!("host:{}", name(n)),
        RData::Mx(m) => format!("mx:{}:{}", m.preference, name(m.host)),
        RData::Srv(s) => format!(
            "srv:{}:{}:{}:{}",
            s.priority,
            s.weight,
            s.port,
            name(s.target)
        ),
        RData::Soa(s) => format!(
            "soa:{}:{}:{}:{}:{}:{}:{}",
            name(s.mname),
            name(s.rname),
            s.serial,
            s.refresh,
            s.retry,
            s.expire,
            s.minimum_ttl
        ),
        RData::Uri(u) => format!("uri:{}:{}:{}", u.priority, u.weight, hex(u.target)),
        RData::Cert(c) => format!(
            "cert:{}:{}:{}:{}",
            c.cert_type,
            c.key_tag,
            c.algorithm,
            hex(c.data)
        ),
    }
}
fn record(r: Record<'_>) -> String {
    format!("{}/{}/{}/{}", name(r.name), r.kind.0, r.class, data(r.data))
}
fn packet(p: Packet<'_, '_>) -> String {
    format!(
        "{}/{:04x}/{}|{}|{}|{}",
        hex(&p.id),
        p.flags,
        p.queries
            .iter()
            .map(|q| query(*q))
            .collect::<Vec<_>>()
            .join(";"),
        p.answers
            .iter()
            .map(|r| record(*r))
            .collect::<Vec<_>>()
            .join(";"),
        p.authority
            .iter()
            .map(|r| record(*r))
            .collect::<Vec<_>>()
            .join(";"),
        p.additional
            .iter()
            .map(|r| record(*r))
            .collect::<Vec<_>>()
            .join(";")
    )
}
fn typed<'a>(kind: &str, rd: &mut Reader<'_>, arena: &mut Arena<'a>) -> RData<'a> {
    match kind {
        "mx" => RData::Mx(rd.mx(arena).unwrap()),
        "soa" => RData::Soa(rd.soa(arena).unwrap()),
        "srv" => RData::Srv(rd.srv(arena).unwrap()),
        "cert" => RData::Cert(rd.cert(arena).unwrap()),
        "uri" => RData::Uri(rd.uri(arena).unwrap()),
        _ => panic!("unknown typed fixture"),
    }
}
#[test]
fn existing_153_c_observations_are_linked_without_promoting_pending_idna() {
    let mut total = 0;
    let mut native = 0;
    let mut pending = 0;
    let mut corrections = 0;
    let mut executed = 0;
    for row in include_str!("c_corpus.tsv").lines() {
        let fields: Vec<_> = row.split('\t').collect();
        assert_eq!(fields.len(), 6);
        let id = fields[0];
        let action = fields[1];
        let input = unhex(fields[2]);
        let arg = fields[3];
        let expected = fields[4];
        let class = fields[5];
        total += 1;
        if class == "native_compare" {
            native += 1;
        } else if class == "pending_idna" {
            pending += 1;
        } else if class.ends_with("variance") || class == "rfc_correction" {
            corrections += 1;
        }
        let mut names = [0; 16384];
        let mut arena = Arena::new(&mut names);
        match action {
            "pending" => {
                assert_eq!(class, "pending_idna");
                continue;
            }
            "profile" => {
                assert_eq!(class, "reference_profile");
                continue;
            }
            "wire-projection" => {
                let n = Name::from_wire(&input).unwrap();
                let mut out = [0; 255];
                let size = n.encode(&mut out).unwrap();
                assert_eq!(hex(&out[..size]), expected, "{id}");
            }
            "name" => {
                let mut rd =
                    Reader::at(&input, arg.parse().unwrap(), input.len(), Limits::DNS).unwrap();
                let parsed = rd.name(&mut arena);
                if expected == "0" {
                    assert!(parsed.is_err(), "{id}");
                } else if let Some(offset) = expected.strip_prefix("accept:") {
                    assert!(parsed.is_ok(), "{id}");
                    assert_eq!(rd.position(), offset.parse::<usize>().unwrap());
                } else {
                    let value = parsed.unwrap();
                    assert_eq!(
                        format!("1:{}:{}", rd.position(), name(value)),
                        expected,
                        "{id}"
                    );
                }
            }
            "query" => {
                let mut rd =
                    Reader::at(&input, arg.parse().unwrap(), input.len(), Limits::DNS).unwrap();
                let value = rd.query(&mut arena);
                if expected == "error" {
                    assert!(value.is_err(), "{id}");
                } else {
                    assert_eq!(query(value.unwrap()), expected, "{id}");
                }
            }
            "record" => {
                let mut rd = Reader::new(&input, Limits::DNS).unwrap();
                let value = rd.record(NOW, &mut arena);
                if expected == "error" {
                    assert!(value.is_err(), "{id}");
                } else {
                    assert_eq!(record(value.unwrap()), expected, "{id}");
                }
            }
            "packet" | "packet-wire" | "dname-native-defect" => {
                let mut qs = [Query::EMPTY; 16];
                let mut rs = [Record::EMPTY; 64];
                let value = Packet::parse(&input, NOW, &mut arena, &mut qs, &mut rs, Limits::DNS);
                if expected == "error" || action == "dname-native-defect" {
                    assert!(value.is_err(), "{id}");
                } else {
                    let value = value.unwrap();
                    if action == "packet" {
                        assert_eq!(packet(value), expected, "{id}");
                    } else {
                        let mut out = [0; 8192];
                        let size = value.encode(NOW, &mut out).unwrap();
                        assert_eq!(hex(&out[..size]), expected, "{id}");
                    }
                }
            }
            "hex" => {
                let (encoded, decoded) = expected.split_once('/').unwrap();
                let mut out = [0xa5; 8192];
                let n = encode_hex_lower(&input, &mut out).unwrap();
                assert_eq!(hex(&out[..n]), encoded, "{id}");
                let n = decode_hex_native(&input, &mut out).unwrap();
                assert_eq!(hex(&out[..n]), decoded, "{id}");
            }
            "typed" | "typed-cap" => {
                let (kind, capacity) = if action == "typed-cap" {
                    let (k, c) = arg.split_once(':').unwrap();
                    (k, Some(c.parse::<usize>().unwrap()))
                } else {
                    (arg, None)
                };
                let mut rd = Reader::new(&input, Limits::DNS).unwrap();
                let mut output = [0xa5; 4096];
                if kind == "query" {
                    let value = rd.query(&mut arena).unwrap();
                    if let Some(cap) = capacity {
                        let mut off = 3;
                        assert_eq!(
                            value.encode_at(&mut output[..cap], &mut off),
                            Err(Error::Capacity)
                        );
                        assert_eq!(off, 3);
                        assert!(output.iter().all(|x| *x == 0xa5));
                    } else {
                        let n = value.encode(&mut output).unwrap();
                        assert_eq!(hex(&output[..n]), expected, "{id}");
                    }
                } else {
                    let value = typed(kind, &mut rd, &mut arena);
                    if let Some(cap) = capacity {
                        let mut off = 3;
                        assert_eq!(
                            value.encode_at(&mut output[..cap], &mut off),
                            Err(Error::Capacity)
                        );
                        assert_eq!(off, 3);
                        assert!(output.iter().all(|x| *x == 0xa5));
                    } else {
                        let n = value.encode(&mut output).unwrap();
                        assert_eq!(hex(&output[..n]), expected, "{id}");
                    }
                }
            }
            "pack-two-query" => {
                let one = Name::from_dotted(b"example.com", &mut arena).unwrap();
                let two = Name::from_dotted(b"second.example", &mut arena).unwrap();
                let q = [
                    Query {
                        name: one,
                        kind: Type::A,
                        class: 1,
                    },
                    Query {
                        name: two,
                        kind: Type::AAAA,
                        class: 1,
                    },
                ];
                let p = Packet::new([0x12, 0x34], 0x8180, &q, &[], &[], &[]);
                let mut out = [0; 128];
                let report = p.pack(NOW, &mut out, arg.parse().unwrap()).unwrap();
                assert!(report.truncated);
                assert_eq!(hex(&out[..report.written]), expected, "{id}");
            }
            "duplicate" => {
                let n = Name::from_dotted(b"owner.example", &mut arena).unwrap();
                let original = Record {
                    name: n,
                    kind: Type(65000),
                    class: 3,
                    expiration: NOW,
                    data: RData::Raw(b"xyz"),
                };
                let mut other = [0; 256];
                let mut dest = Arena::new(&mut other);
                let copied = original.duplicate_into(&mut dest).unwrap();
                assert_eq!(copied, original);
                assert_ne!(copied.name.wire().as_ptr(), original.name.wire().as_ptr());
            }
            _ => panic!("unclassified action {action}"),
        }
        executed += 1;
    }
    assert_eq!(total, 153);
    assert!(native > 50);
    assert!(pending > 0);
    assert!(corrections > 0);
    assert!(executed > 80);
    if let Some(path) = std::env::var_os("GNUNET_DNS_CORPUS_REPORT") {
        std::fs::write(path,format!("{{\"total\":{total},\"executed_wire_or_field_actions\":{executed},\"native_comparison_rows\":{native},\"pending_idna_rows\":{pending},\"explicit_correction_or_variance_rows\":{corrections},\"full_idna_verified\":false}}\n")).unwrap();
    }
}
