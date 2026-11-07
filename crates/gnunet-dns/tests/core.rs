//! Functional, ownership and bounded refusal tests for the DNS core.
#![expect(
    clippy::unwrap_used,
    reason = "Tests require successful prerequisite construction and exact independent reference fixtures."
)]
use gnunet_dns::*;
const NOW: AbsoluteTime = AbsoluteTime::from_micros(100_000_000);
const LIM: Limits = Limits::DNS;
fn name<'a>(input: &[u8], arena: &mut Arena<'a>) -> Name<'a> {
    Name::from_dotted(input, arena).unwrap()
}
#[test]
fn compressed_names_forward_cycles_depth_and_bounds() {
    let plain = b"\x03www\x07example\x03com\0";
    for (data, offset, wanted) in [
        (plain.to_vec(), 0, b"www.example.com".as_slice()),
        (
            [plain.as_slice(), b"\xc0\0"].concat(),
            plain.len(),
            b"www.example.com",
        ),
        (
            [b"\xc0\x02", plain.as_slice()].concat(),
            0,
            b"www.example.com",
        ),
        (
            [plain.as_slice(), b"\x01x\xc0\0"].concat(),
            plain.len(),
            b"x.www.example.com",
        ),
    ] {
        let mut storage = [0; 512];
        let mut a = Arena::new(&mut storage);
        let mut rd = Reader::at(&data, offset, data.len(), LIM).unwrap();
        let n = rd.name(&mut a).unwrap();
        let mut out = [0; 256];
        let len = n.write_dotted(&mut out).unwrap();
        assert_eq!(&out[..len], wanted);
    }
    for data in [
        b"\xc0".as_slice(),
        b"\x03ab",
        b"\x40\0",
        b"\x80\0",
        b"\xc0\xff",
        b"\xc0\0",
    ] {
        let mut a_storage = [0; 256];
        let mut a = Arena::new(&mut a_storage);
        let mut rd = Reader::new(data, LIM).unwrap();
        assert!(rd.name(&mut a).is_err());
        assert_eq!(rd.position(), 0);
        assert_eq!(a.used(), 0);
    }
    for depth in [32, 33, 34] {
        let mut packet = Vec::new();
        for i in 0..depth {
            let target = (i + 1) * 2;
            packet.extend_from_slice(&[0xc0 | ((target >> 8) as u8), (target & 255) as u8]);
        }
        packet.push(0);
        let mut storage = [0; 256];
        let mut a = Arena::new(&mut storage);
        let mut rd = Reader::new(
            &packet,
            Limits {
                maximum_compression_hops: usize::MAX,
                ..LIM
            },
        )
        .unwrap();
        assert_eq!(rd.name(&mut a).is_ok(), depth <= 33);
    }
    let mut storage = [0; 256];
    let mut a = Arena::new(&mut storage);
    let mut rd = Reader::new(
        plain,
        Limits {
            maximum_work: 1,
            ..LIM
        },
    )
    .unwrap();
    assert_eq!(rd.name(&mut a), Err(Error::Capacity));
}
fn all_records<'a>(n: Name<'a>) -> [Record<'a>; 11] {
    let make = |kind, data| Record {
        name: n,
        kind,
        class: 3,
        expiration: ttl_expiration(123, NOW),
        data,
    };
    [
        make(Type::NS, RData::Hostname(n)),
        make(Type::CNAME, RData::Hostname(n)),
        make(Type::PTR, RData::Hostname(n)),
        make(Type::DNAME, RData::Hostname(n)),
        make(
            Type::MX,
            RData::Mx(Mx {
                preference: 513,
                host: n,
            }),
        ),
        make(
            Type::SRV,
            RData::Srv(Srv {
                priority: 1,
                weight: 2,
                port: 443,
                target: n,
            }),
        ),
        make(
            Type::SOA,
            RData::Soa(Soa {
                mname: n,
                rname: n,
                serial: 0x12345678,
                refresh: 123,
                retry: 456,
                expire: 789,
                minimum_ttl: 321,
            }),
        ),
        make(
            Type::CERT,
            RData::Cert(Cert {
                cert_type: 65535,
                key_tag: 0x1234,
                algorithm: 255,
                data: b"\0\xffabc",
            }),
        ),
        make(
            Type::URI,
            RData::Uri(Uri {
                priority: 7,
                weight: 9,
                target: b"https://example/x",
            }),
        ),
        make(Type::A, RData::Raw(b"\x01\x02\x03")),
        make(Type(65000), RData::Raw(b"\0raw\xff")),
    ]
}
#[test]
fn full_four_section_roundtrip_all_typed_and_raw() {
    let mut storage = [0; 512];
    let mut a = Arena::new(&mut storage);
    let n = name(b"example.com", &mut a);
    let records = all_records(n);
    let qs = [Query {
        name: n,
        kind: Type::ALL,
        class: 3,
    }];
    let p = Packet::new(
        [0x12, 0x34],
        0xffff,
        &qs,
        &records[..5],
        &records[5..8],
        &records[8..],
    );
    let mut wire = [0xa5; 4096];
    let size = p.encode(NOW, &mut wire).unwrap();
    assert!(wire[size..].iter().all(|b| *b == 0xa5));
    let mut names = [0; 4096];
    let mut arena = Arena::new(&mut names);
    let mut q = [Query::EMPTY; 1];
    let mut r = [Record::EMPTY; 11];
    let parsed = Packet::parse(&wire[..size], NOW, &mut arena, &mut q, &mut r, LIM).unwrap();
    assert_eq!(parsed.id, p.id);
    assert_eq!(parsed.flags, p.flags);
    assert_eq!(parsed.queries, p.queries);
    assert_eq!(parsed.answers, p.answers);
    assert_eq!(parsed.authority, p.authority);
    assert_eq!(parsed.additional, p.additional);
    assert!(parsed.trailing.is_empty());
}
#[test]
fn cert_five_byte_uri_full_tail_dname_and_unknown_widths() {
    let mut storage = [0; 512];
    let mut a = Arena::new(&mut storage);
    let n = name(b"target.example", &mut a);
    let cert = Cert {
        cert_type: 1,
        key_tag: 0x1234,
        algorithm: 13,
        data: b"\x01\0\xff",
    };
    let mut out = [0xa5; 128];
    let size = cert.encode(&mut out).unwrap();
    assert_eq!(&out[..size], b"\0\x01\x12\x34\x0d\x01\0\xff");
    let mut rd = Reader::new(&out[..size], LIM).unwrap();
    assert_eq!(rd.cert(&mut a).unwrap(), cert);
    assert_eq!(rd.position(), size);
    let empty = Cert { data: b"", ..cert };
    assert_eq!(empty.encode(&mut out).unwrap(), 5);
    assert_eq!(
        Reader::new(&out[..5], LIM).unwrap().cert(&mut a).unwrap(),
        empty
    );
    let uri = Uri {
        priority: 7,
        weight: 9,
        target: b"https://example/x",
    };
    let size = uri.encode(&mut out).unwrap();
    assert_eq!(size, 4 + uri.target.len());
    assert_eq!(
        Reader::new(&out[..size], LIM).unwrap().uri(&mut a).unwrap(),
        uri
    );
    assert_eq!(
        Uri { target: b"", ..uri }.encode(&mut out),
        Err(Error::Malformed)
    );
    let r = Record {
        name: n,
        kind: Type::DNAME,
        class: 1,
        expiration: NOW,
        data: RData::Hostname(n),
    };
    let size = r.encode(NOW, &mut out).unwrap();
    assert_eq!(
        &out[n.wire_len() + 8..n.wire_len() + 10],
        &(n.wire_len() as u16).to_be_bytes()
    );
    assert_eq!(
        Reader::new(&out[..size], LIM)
            .unwrap()
            .record(NOW, &mut a)
            .unwrap(),
        r
    );
}
#[test]
fn every_encoder_capacity_and_invalid_data_refuse_atomically() {
    let mut storage = [0; 512];
    let mut a = Arena::new(&mut storage);
    let n = name(b"x.example", &mut a);
    let records = all_records(n);
    for r in records {
        let size = r.encoded_len().unwrap();
        for cap in 0..size {
            let mut out = vec![0xa5; size + 3];
            assert_eq!(r.encode(NOW, &mut out[..cap]), Err(Error::Capacity));
            assert!(out.iter().all(|b| *b == 0xa5));
        }
        let size = r.data.encoded_len().unwrap();
        for cap in 0..size {
            let mut out = vec![0xa5; size + 3];
            assert_eq!(r.data.encode(&mut out[..cap]), Err(Error::Capacity));
            assert!(out.iter().all(|b| *b == 0xa5));
        }
    }
    let q = Query {
        name: n,
        kind: Type(65535),
        class: 65535,
    };
    let mut out = [0xa5; 256];
    let mut cursor = 3;
    assert_eq!(
        q.encode_at(&mut out[..4], &mut cursor),
        Err(Error::Capacity)
    );
    assert_eq!(cursor, 3);
    assert_eq!(out, [0xa5; 256]);
    let bad = Record {
        kind: Type::MX,
        data: RData::Raw(b"bad"),
        ..Record::EMPTY
    };
    let rs = [bad];
    let p = Packet::new([1, 2], 0, &[], &rs, &[], &[]);
    assert_eq!(p.pack(NOW, &mut out, 12), Err(Error::InvalidInput));
    assert_eq!(out, [0xa5; 256]);
    let big = vec![0; 65536];
    assert_eq!(RData::Raw(&big).encode(&mut out), Err(Error::TooLarge));
    assert_eq!(out, [0xa5; 256]);
}
#[test]
fn pack_correct_counts_tc_complete_output_and_separate_sections() {
    let mut storage = [0; 512];
    let mut a = Arena::new(&mut storage);
    let one = name(b"example.com", &mut a);
    let two = name(b"second.example", &mut a);
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
    let mut out = [0xa5; 128];
    for (cap, written, count) in [
        (12, 12, 0),
        (20, 12, 0),
        (29, 29, 1),
        (30, 29, 1),
        (45, 29, 1),
    ] {
        out.fill(0xa5);
        let result = p.pack(NOW, &mut out, cap).unwrap();
        assert!(result.truncated);
        assert_eq!(result.written, written);
        assert_eq!(result.counts.queries, count);
        assert_eq!(&out[4..6], &count.to_be_bytes());
        assert_eq!(&out[2..4], &0x8380_u16.to_be_bytes());
        assert!(out[written..].iter().all(|b| *b == 0xa5));
    }
    out.fill(0xa5);
    let length = p.encoded_len().unwrap();
    assert_eq!(p.encode(NOW, &mut out[..length - 1]), Err(Error::Capacity));
    assert_eq!(out, [0xa5; 128]);
    let report = p.pack(NOW, &mut out, 128).unwrap();
    assert!(!report.truncated);
    assert_eq!(report.counts.queries, 2);
}
#[test]
fn ttl_explicit_clock_floor_saturation_and_native_never() {
    assert_eq!(ttl_expiration(0, NOW), NOW);
    assert_eq!(
        ttl_expiration(u32::MAX, NOW).as_micros(),
        100_000_000 + u64::from(u32::MAX) * 1_000_000
    );
    assert_eq!(
        expiration_ttl(
            AbsoluteTime::from_micros(NOW.as_micros() + 123_456_789),
            NOW
        ),
        123
    );
    assert_eq!(
        expiration_ttl(AbsoluteTime::from_micros(NOW.as_micros() + 999_999), NOW),
        0
    );
    assert_eq!(expiration_ttl(AbsoluteTime::UNIX_EPOCH, NOW), 0);
    assert_eq!(expiration_ttl(AbsoluteTime::NEVER, NOW), 4_154_504_685);
    assert_eq!(
        ttl_expiration(u32::MAX, AbsoluteTime::NEVER),
        AbsoluteTime::NEVER
    );
}
#[test]
fn clone_full_packet_is_independent_with_exact_destination_storage() {
    let mut dest = [0; 4096];
    let mut a = Arena::new(&mut dest);
    let mut qslots = [Query::EMPTY; 1];
    let mut rslots = [Record::EMPTY; 11];
    let mut expected = [0; 4096];
    let expected_size;
    let copied = {
        let mut source = [0; 512];
        let mut src = Arena::new(&mut source);
        let n = name(b"owner.example", &mut src);
        let records = all_records(n);
        let qs = [Query {
            name: n,
            kind: Type::A,
            class: 1,
        }];
        let p = Packet::new([9, 8], 0x8180, &qs, &records, &[], &[]);
        expected_size = p.encode(NOW, &mut expected).unwrap();
        p.duplicate_into(&mut a, &mut qslots, &mut rslots).unwrap()
    };
    let mut output = [0; 4096];
    assert_eq!(copied.encode(NOW, &mut output).unwrap(), expected_size);
    assert_eq!(&output[..expected_size], &expected[..expected_size]);
    for r in copied.answers {
        let required = r.name.wire_len() + r.data.copied_bytes().unwrap();
        let mut dest = vec![0; required];
        let mut a = Arena::new(&mut dest);
        let clone = r.duplicate_into(&mut a).unwrap();
        assert_eq!(clone, *r);
        assert_eq!(a.used(), required);
    }
}
#[test]
fn parser_short_capacity_work_and_slot_error_cleanup() {
    for n in 0..12 {
        let input = vec![0; n];
        let mut bytes = [0; 512];
        let mut a = Arena::new(&mut bytes);
        assert_eq!(
            Packet::parse(&input, NOW, &mut a, &mut [], &mut [], LIM),
            Err(Error::Truncated)
        );
    }
    let input = b"\x12\x34\x81\x80\0\x01\0\0\0\0\0\0\x01x\0\0\x01";
    let mut bytes = [0; 512];
    let mut a = Arena::new(&mut bytes);
    let mut qs = [Query::EMPTY; 1];
    let mut rs = [];
    assert!(Packet::parse(input, NOW, &mut a, &mut qs, &mut rs, LIM).is_err());
    assert_eq!(qs, [Query::EMPTY]);
    let mut bytes = [0; 512];
    let mut a = Arena::new(&mut bytes);
    let mut qs = [];
    assert_eq!(
        Packet::parse(input, NOW, &mut a, &mut qs, &mut [], LIM),
        Err(Error::Capacity)
    );
    assert_eq!(a.used(), 0);
    let mut bytes = [];
    let mut a = Arena::new(&mut bytes);
    let mut rd = Reader::new(b"\x01x\0", LIM).unwrap();
    assert_eq!(rd.name(&mut a), Err(Error::Capacity));
    assert_eq!(rd.position(), 0);
}
#[test]
fn lowlevel_typed_truncations_and_rdata_end_do_not_escape() {
    let mut storage = [0; 256];
    let mut arena = Arena::new(&mut storage);
    let n = name(b"n", &mut arena);
    let records = all_records(n);
    for record in records {
        let mut bytes = [0; 512];
        let size = record.encode(NOW, &mut bytes).unwrap();
        for length in 0..size {
            let mut names = [0; 512];
            let mut a = Arena::new(&mut names);
            let mut rd = Reader::new(&bytes[..length], LIM).unwrap();
            assert!(rd.record(NOW, &mut a).is_err());
            assert_eq!(rd.position(), 0);
        }
    }
    let input = b"\0\x01\0\x01\x0dABC\xfftail";
    let mut names = [0; 32];
    let mut a = Arena::new(&mut names);
    let mut rd = Reader::at(input, 0, 8, LIM).unwrap();
    assert_eq!(rd.cert(&mut a).unwrap().data, b"ABC");
    assert_eq!(rd.position(), 8);
    let c = CaaHeader::parse(b"\x80\x05issueca.example").unwrap();
    assert_eq!(c.tag(b"\x80\x05issueca.example").unwrap(), b"issue");
    assert_eq!(c.value(b"\x80\x05issueca.example").unwrap(), b"ca.example");
    assert_eq!(CaaHeader::parse(b"\0\xffx"), Err(Error::Truncated));
}
struct Missing;
impl Idna for Missing {
    fn to_ascii(&self, _: &[u8], _: &mut [u8]) -> Result<usize, Error> {
        Err(Error::Unavailable)
    }
    fn to_unicode_label(&self, _: &[u8], _: &mut [u8]) -> Result<usize, Error> {
        Err(Error::Unavailable)
    }
}
struct AsciiTestOnly;
impl Idna for AsciiTestOnly {
    fn to_ascii(&self, b: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if !b.is_ascii() {
            return Err(Error::Unavailable);
        }
        if b.len() > out.len() {
            return Err(Error::Capacity);
        }
        for (i, c) in b.iter().enumerate() {
            out[i] = c.to_ascii_lowercase();
        }
        Ok(b.len())
    }
    fn to_unicode_label(&self, b: &[u8], out: &mut [u8]) -> Result<usize, Error> {
        if b.starts_with(b"xn--") {
            return Err(Error::Malformed);
        }
        if b.len() > out.len() {
            return Err(Error::Capacity);
        }
        out[..b.len()].copy_from_slice(b);
        Ok(b.len())
    }
}
#[test]
fn idna_is_explicit_and_no_unavailable_backend_fallback() {
    let mut storage = [0; 512];
    let mut a = Arena::new(&mut storage);
    let mut work = [0; 512];
    assert_eq!(
        Name::from_native_text(b"example", &Missing, &mut work, &mut a, LIM),
        Err(Error::Unavailable)
    );
    assert_eq!(a.used(), 0);
    let n = name(b"xn--bcher-kva.example", &mut a);
    let mut out = [0xa5; 128];
    assert_eq!(
        n.write_native_text(&Missing, &mut work, &mut out),
        Err(Error::Unavailable)
    );
    assert_eq!(out, [0xa5; 128]);
    let len = n
        .write_native_text(&AsciiTestOnly, &mut work, &mut out)
        .unwrap();
    assert_eq!(&out[..len], b"xn--bcher-kva.example");
    assert!(check_name(b"@", &AsciiTestOnly, &mut work, LIM).is_err());
    let n = Name::from_native_text(b"@", &AsciiTestOnly, &mut work, &mut a, LIM).unwrap();
    assert_eq!(n.wire(), b"\x01@\0");
    let n = Name::from_native_text(b"a..b", &AsciiTestOnly, &mut work, &mut a, LIM).unwrap();
    assert_eq!(n.wire(), b"\x01a\0");
    assert!(Name::from_dotted(b"a..b", &mut a).is_err());
}
#[test]
fn native_hex_values_partial_pairs_and_atomic_capacity() {
    for (input, expected) in [
        (b"00aF".as_slice(), b"\0\xaf".as_slice()),
        (b"aZ", b"\x0a"),
        (b"ZZ", b""),
        (b"1x", b"\x01"),
        (b" 1", b"\x01"),
        (b"-1", b"\xff"),
        (b"+1", b"\x01"),
        (b"0x", b"\0"),
        (b"a", b""),
    ] {
        let mut out = [0xa5; 32];
        let n = decode_hex_native(input, &mut out).unwrap();
        assert_eq!(&out[..n], expected);
        assert!(out[n..].iter().all(|b| *b == 0xa5));
    }
    let mut out = [0xa5; 32];
    assert_eq!(
        decode_hex_native(b"0011", &mut out[..1]),
        Err(Error::Capacity)
    );
    assert_eq!(out, [0xa5; 32]);
    assert_eq!(encode_hex_lower(b"\0\xaf\xff", &mut out).unwrap(), 6);
    assert_eq!(&out[..6], b"00afff");
}

#[test]
fn exhaustive_actual_c_native_hex_pair_oracle() {
    let mut expected = vec![None; 65536];
    let mut accepted = 0;
    for row in include_str!("hex_pairs.tsv").lines() {
        let (key, value) = row.split_once('\t').unwrap();
        let index = usize::from(u16::from_str_radix(key, 16).unwrap());
        assert!(expected[index].is_none());
        expected[index] = Some(u8::from_str_radix(value, 16).unwrap());
        accepted += 1;
    }
    assert_eq!(accepted, 5786);
    for a in 0..=255_u16 {
        for b in 0..=255_u16 {
            let input = [a as u8, b as u8];
            let mut output = [0xa5];
            let n = decode_hex_native(&input, &mut output).unwrap();
            match expected[usize::from(a) * 256 + usize::from(b)] {
                Some(value) => {
                    assert_eq!(n, 1, "{a:02x}{b:02x}");
                    assert_eq!(output, [value], "{a:02x}{b:02x}");
                }
                None => {
                    assert_eq!(n, 0, "{a:02x}{b:02x}");
                    assert_eq!(output, [0xa5]);
                }
            }
        }
    }
}

#[test]
fn parsed_payloads_survive_input_reuse_and_storage_slots_can_be_reused() {
    let mut names = [0; 2048];
    let mut a = Arena::new(&mut names);
    let mut q = [Query::EMPTY; 1];
    let mut r = [Record::EMPTY; 3];
    let parsed = {
        let mut builder_storage = [0; 256];
        let mut b = Arena::new(&mut builder_storage);
        let n = name(b"owner.example", &mut b);
        let raw = vec![0, 1, 2, 255];
        let uri = String::from("https://example/path");
        let certificate = vec![4, 5, 0, 255];
        let records = [
            Record {
                name: n,
                kind: Type(65000),
                class: 1,
                expiration: NOW,
                data: RData::Raw(&raw),
            },
            Record {
                name: n,
                kind: Type::URI,
                class: 1,
                expiration: NOW,
                data: RData::Uri(Uri {
                    priority: 1,
                    weight: 2,
                    target: uri.as_bytes(),
                }),
            },
            Record {
                name: n,
                kind: Type::CERT,
                class: 1,
                expiration: NOW,
                data: RData::Cert(Cert {
                    cert_type: 1,
                    key_tag: 3,
                    algorithm: 13,
                    data: &certificate,
                }),
            },
        ];
        let qs = [Query {
            name: n,
            kind: Type::A,
            class: 1,
        }];
        let p = Packet::new([1, 2], 0, &qs, &records, &[], &[]);
        let mut input = vec![0; 1024];
        let n = p.encode(NOW, &mut input).unwrap();
        let result = Packet::parse(&input[..n], NOW, &mut a, &mut q, &mut r, LIM).unwrap();
        input.fill(0xff);
        result
    };
    assert_eq!(parsed.answers[0].data, RData::Raw(&[0, 1, 2, 255]));
    assert!(matches!(
        parsed.answers[1].data,
        RData::Uri(Uri {
            target: b"https://example/path",
            ..
        })
    ));
    assert!(matches!(
        parsed.answers[2].data,
        RData::Cert(Cert {
            data: [4, 5, 0, 255],
            ..
        })
    ));
    q.fill(Query::EMPTY);
    r.fill(Record::EMPTY);
    assert_eq!(q[0], Query::EMPTY);
    assert_eq!(r[2], Record::EMPTY);
}
#[test]
fn standalone_duplicate_operations_cover_every_typed_owned_payload() {
    let mut dest = [0; 4096];
    let mut a = Arena::new(&mut dest);
    let copies = {
        let mut source = [0; 256];
        let mut src = Arena::new(&mut source);
        let n = name(b"x.example", &mut src);
        let body = vec![0, 5, 255];
        let uri = String::from("https://example/x");
        let payloads = [
            RData::Soa(Soa {
                mname: n,
                rname: n,
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum_ttl: 5,
            }),
            RData::Mx(Mx {
                preference: 9,
                host: n,
            }),
            RData::Srv(Srv {
                priority: 1,
                weight: 2,
                port: 443,
                target: n,
            }),
            RData::Uri(Uri {
                priority: 7,
                weight: 8,
                target: uri.as_bytes(),
            }),
            RData::Cert(Cert {
                cert_type: 65535,
                key_tag: 1,
                algorithm: 255,
                data: &body,
            }),
            RData::Raw(&body),
        ];
        let mut copies = [RData::Raw(&[]); 6];
        for (i, d) in payloads.into_iter().enumerate() {
            copies[i] = match d {
                RData::Soa(v) => RData::Soa(v.duplicate_into(&mut a).unwrap()),
                RData::Mx(v) => RData::Mx(v.duplicate_into(&mut a).unwrap()),
                RData::Srv(v) => RData::Srv(v.duplicate_into(&mut a).unwrap()),
                RData::Uri(v) => RData::Uri(v.duplicate_into(&mut a).unwrap()),
                RData::Cert(v) => RData::Cert(v.duplicate_into(&mut a).unwrap()),
                _ => d.duplicate_into(&mut a).unwrap(),
            };
            assert_eq!(copies[i], d);
        }
        copies
    };
    assert_eq!(copies[5], RData::Raw(&[0, 5, 255]));
    assert!(matches!(
        copies[4],
        RData::Cert(Cert {
            data: [0, 5, 255],
            ..
        })
    ));
    let mut output = [0; 256];
    for copied in copies {
        assert!(copied.encode(&mut output).is_ok());
    }
}

#[test]
fn emit_fresh_rust_packet_and_safe_c_variance_vectors() {
    let mut storage = [0; 1024];
    let mut arena = Arena::new(&mut storage);
    let n = name(b"owner.example", &mut arena);
    let all = all_records(n);
    let q = [Query {
        name: n,
        kind: Type::ALL,
        class: 3,
    }];
    // CERT's C record parser is unsafe; URI's native parser has a known length
    // defect. Their RFC vectors are emitted separately, never fed to that C path.
    let compatible = [
        all[0], all[1], all[2], all[3], all[4], all[5], all[6], all[9], all[10],
    ];
    let p = Packet::new(
        [0x12, 0x34],
        0x8180,
        &q,
        &compatible[..4],
        &compatible[4..7],
        &compatible[7..],
    );
    let mut output = [0; 4096];
    let nbytes = p.encode(NOW, &mut output).unwrap();
    assert_eq!(&output[..4], b"\x12\x34\x81\x80");
    assert_eq!(
        p.counts().unwrap(),
        Counts {
            queries: 1,
            answers: 4,
            authority: 3,
            additional: 2
        }
    );
    if let Some(dir) = std::env::var_os("GNUNET_DNS_CORE_OUTPUT") {
        let dir = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("rust.packet"), &output[..nbytes]).unwrap();
        let n = all[3].encode(NOW, &mut output).unwrap();
        std::fs::write(dir.join("rust.dname.record"), &output[..n]).unwrap();
        let n = all[8].encode(NOW, &mut output).unwrap();
        std::fs::write(dir.join("rust.uri.record"), &output[..n]).unwrap();
        let n = all[7].data.encode(&mut output).unwrap();
        std::fs::write(dir.join("rust.cert.rfc.rdata"), &output[..n]).unwrap();
    }
}

#[test]
fn impossible_counts_and_unwritten_slots_are_untouched() {
    let marker = Query {
        kind: Type::ALL,
        class: 65535,
        ..Query::EMPTY
    };
    let old = Record {
        kind: Type(65000),
        class: 65535,
        ..Record::EMPTY
    };
    let mut names = [0; 512];
    let mut arena = Arena::new(&mut names);
    let mut queries = [marker; 4];
    let mut records = [old; 4];
    let short = b"\0\x01\0\0\0\x04\0\x04\0\0\0\0";
    assert_eq!(
        Packet::parse(short, NOW, &mut arena, &mut queries, &mut records, LIM),
        Err(Error::Truncated)
    );
    assert_eq!(queries, [marker; 4]);
    assert_eq!(records, [old; 4]);
    assert_eq!(arena.used(), 0);
    // The minimum length passes but the second name is malformed. The first
    // completed query is cleared; slots never assigned by this attempt stay put.
    let malformed = b"\0\x01\0\0\0\x02\0\0\0\0\0\0\0\0\x01\0\x01\x40\0\0\0\0";
    assert!(Packet::parse(malformed, NOW, &mut arena, &mut queries, &mut records, LIM).is_err());
    assert_eq!(queries[0], Query::EMPTY);
    assert_eq!(queries[1], marker);
    assert_eq!(queries[3], marker);
    assert_eq!(records, [old; 4]);
}
