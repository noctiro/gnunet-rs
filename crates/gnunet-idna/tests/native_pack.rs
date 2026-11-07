//! Native text graph staging, exact native capacity needs, and atomic resource refusal.
#![expect(
    clippy::unwrap_used,
    reason = "Tests require successful prerequisite fixture construction and exact operation results."
)]
#![expect(
    clippy::panic,
    reason = "A wrong typed fixture variant must fail rather than silently omit the assertion."
)]
use gnunet_dns::*;
use gnunet_idna::{Backend, Limits as ILimits, NativeProfile, Workspace};
const NOW: AbsoluteTime = AbsoluteTime::UNIX_EPOCH;
const PROFILE: NativeProfile = NativeProfile::Libunistring1_5Unicode18_0;
fn name<'a>(s: &[u8], arena: &mut Arena<'a>) -> Name<'a> {
    Name::from_dotted(s, arena).unwrap()
}
#[test]
fn semantic_no_stops_only_current_section_and_later_sections_continue() {
    let mut bytes = [0; 4096];
    let mut a = Arena::new(&mut bytes);
    let valid = name(b"EXAMPLE", &mut a);
    let bad = name(b"\xff", &mut a);
    let emoji = name(b"xn--e28h", &mut a);
    let q = [
        Query {
            name: valid,
            kind: Type::A,
            class: 1,
        },
        Query {
            name: bad,
            kind: Type::A,
            class: 1,
        },
        Query {
            name: valid,
            kind: Type::A,
            class: 1,
        },
    ];
    let record = Record {
        name: valid,
        kind: Type::CNAME,
        class: 1,
        expiration: NOW,
        data: RData::Hostname(valid),
    };
    let bad_record = Record {
        data: RData::Hostname(emoji),
        ..record
    };
    let answers = [record, bad_record, record];
    let authority = [record];
    let additional = [record];
    let packet = Packet::new([1, 2], 0x0100, &q, &answers, &authority, &additional);
    let original_q = q;
    let mut idna = Workspace::new();
    let backend = Backend::new(&mut idna, ILimits::GNUNET, PROFILE);
    let mut work = [0; 4096];
    let mut text = [0; 4096];
    let mut scratch = NativeScratch::new(&mut work, &mut text, Limits::DNS);
    let mut copied = [0; 4096];
    let mut arena = Arena::new(&mut copied);
    let mut qs = [Query::EMPTY; 8];
    let mut rs = [Record::EMPTY; 8];
    let mut output = [0xa5; 512];
    let report = packet
        .pack_native(
            NOW,
            &backend,
            &mut scratch,
            &mut arena,
            &mut qs,
            &mut rs,
            &mut output,
            512,
        )
        .unwrap();
    assert_eq!(
        report.counts,
        Counts {
            queries: 1,
            answers: 1,
            authority: 1,
            additional: 1
        }
    );
    assert!(report.truncated);
    assert_eq!(report.native_size, None);
    assert_eq!(q, original_q);
    assert_ne!(output[2] & 2, 0);
    let mut parsed = [0; 4096];
    let mut arena = Arena::new(&mut parsed);
    let mut pqs = [Query::EMPTY; 8];
    let mut prs = [Record::EMPTY; 8];
    let p = Packet::parse(
        &output[..report.written],
        NOW,
        &mut arena,
        &mut pqs,
        &mut prs,
        Limits::DNS,
    )
    .unwrap();
    assert_eq!(p.queries[0].name.wire(), b"\x07example\0");
    assert_eq!(p.authority.len(), 1);
    assert_eq!(p.additional.len(), 1);
}
#[test]
fn full_form_clones_raw_payloads_and_all_typed_names_without_source_changes() {
    let mut data = [0; 4096];
    let mut source = Arena::new(&mut data);
    let mixed = name(b"MIXED.Example", &mut source);
    let unicode = name("é.example".as_bytes(), &mut source);
    let at = name(b"@", &mut source);
    let q = [Query {
        name: at,
        kind: Type::A,
        class: 1,
    }];
    let records = [
        Record {
            name: mixed,
            kind: Type::SOA,
            class: 1,
            expiration: NOW,
            data: RData::Soa(Soa {
                mname: unicode,
                rname: mixed,
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum_ttl: 5,
            }),
        },
        Record {
            name: mixed,
            kind: Type::MX,
            class: 1,
            expiration: NOW,
            data: RData::Mx(Mx {
                preference: 7,
                host: unicode,
            }),
        },
        Record {
            name: mixed,
            kind: Type::SRV,
            class: 1,
            expiration: NOW,
            data: RData::Srv(Srv {
                priority: 1,
                weight: 2,
                port: 3,
                target: unicode,
            }),
        },
        Record {
            name: mixed,
            kind: Type::TXT,
            class: 1,
            expiration: NOW,
            data: RData::Raw(b"opaque\0bytes"),
        },
        Record {
            name: mixed,
            kind: Type::URI,
            class: 1,
            expiration: NOW,
            data: RData::Uri(Uri {
                priority: 1,
                weight: 2,
                target: b"https://URI.Example/x",
            }),
        },
    ];
    let packet = Packet::new([1, 2], 0, &q, &records, &[], &[]);
    let original = records;
    let mut idna = Workspace::new();
    let backend = Backend::new(&mut idna, ILimits::GNUNET, PROFILE);
    let mut work = [0; 4096];
    let mut text = [0; 4096];
    let mut scratch = NativeScratch::new(&mut work, &mut text, Limits::DNS);
    let mut destination = [0; 4096];
    let mut arena = Arena::new(&mut destination);
    let mut qs = [Query::EMPTY; 1];
    let mut rs = [Record::EMPTY; 5];
    let p = packet
        .native_builder_form(&backend, &mut scratch, &mut arena, &mut qs, &mut rs)
        .unwrap();
    assert_eq!(records, original);
    assert_eq!(p.queries[0].name.wire(), b"\x01@\0");
    assert_eq!(p.answers[0].name.wire(), b"\x05mixed\x07example\0");
    let RData::Soa(soa) = p.answers[0].data else {
        panic!("SOA")
    };
    assert_eq!(soa.mname.wire(), b"\x07xn--9ca\x07example\0");
    assert_eq!(soa.serial, 1);
    let RData::Raw(b) = p.answers[3].data else {
        panic!("raw")
    };
    assert_eq!(b, b"opaque\0bytes");
    assert_ne!(b.as_ptr(), b"opaque\0bytes".as_ptr());
    let RData::Uri(uri) = p.answers[4].data else {
        panic!("uri")
    };
    assert_eq!(uri.target, b"https://URI.Example/x");
    let mut copied = [0; 4096];
    let mut arena = Arena::new(&mut copied);
    let mut qs = [Query::EMPTY; 1];
    let mut rs = [Record::EMPTY; 5];
    let duplicate = p.duplicate_into(&mut arena, &mut qs, &mut rs).unwrap();
    assert_eq!(duplicate, p);
}
struct AsciiFailure<'a, 'b> {
    backend: &'a Backend<'b>,
    error: Error,
}
impl Idna for AsciiFailure<'_, '_> {
    fn to_ascii(&self, _: &[u8], _: &mut [u8]) -> Result<usize, Error> {
        Err(self.error)
    }
    fn to_unicode_label(&self, b: &[u8], o: &mut [u8]) -> Result<usize, Error> {
        self.backend.to_unicode_label(b, o)
    }
}
#[test]
fn resource_unavailable_and_insufficient_destinations_never_become_tc() {
    let mut source_bytes = [0; 255];
    let mut source_arena = Arena::new(&mut source_bytes);
    let q = [Query {
        name: name(b"abc", &mut source_arena),
        kind: Type::A,
        class: 1,
    }];
    let p = Packet::new([1, 2], 0, &q, &[], &[], &[]);
    let mut idna = Workspace::new();
    let backend = Backend::new(&mut idna, ILimits::GNUNET, PROFILE);
    for e in [
        Error::Capacity,
        Error::TooLarge,
        Error::Unavailable,
        Error::Overflow,
    ] {
        let failing = AsciiFailure {
            backend: &backend,
            error: e,
        };
        let mut work = [0; 4096];
        let mut text = [0; 4096];
        let mut scratch = NativeScratch::new(&mut work, &mut text, Limits::DNS);
        let mut bytes = [0; 255];
        let mut arena = Arena::new(&mut bytes);
        let mut qs = [Query::EMPTY; 1];
        let mut out = [0xa5; 512];
        assert_eq!(
            p.pack_native(
                NOW,
                &failing,
                &mut scratch,
                &mut arena,
                &mut qs,
                &mut [],
                &mut out,
                512
            ),
            Err(e)
        );
        assert_eq!(out, [0xa5; 512]);
    }
    for mode in 0..4 {
        let mut work = [0; 4096];
        let mut text = [0; 4096];
        let (w, t) = if mode == 0 {
            (&mut work[..0], &mut text[..])
        } else if mode == 1 {
            (&mut work[..], &mut text[..0])
        } else {
            (&mut work[..], &mut text[..])
        };
        let mut scratch = NativeScratch::new(w, t, Limits::DNS);
        let mut bytes = [0; 255];
        let mut arena = Arena::new(if mode == 2 {
            &mut bytes[..0]
        } else {
            &mut bytes[..]
        });
        let mut qs = [Query::EMPTY; 1];
        let slots = if mode == 3 { &mut qs[..0] } else { &mut qs[..] };
        let mut out = [0xa5; 512];
        assert!(
            p.pack_native(
                NOW,
                &backend,
                &mut scratch,
                &mut arena,
                slots,
                &mut [],
                &mut out,
                512
            )
            .is_err()
        );
        assert_eq!(out, [0xa5; 512]);
    }
}
#[test]
fn compression_projection_failure_is_not_a_lookup_no() {
    let label = b"xn--j50iaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let mut input = vec![label.len() as u8];
    input.extend_from_slice(label);
    input.push(0);
    let off = input.len();
    input.extend_from_slice(b"\xc0\0");
    let mut bytes = [0; 4096];
    let mut arena = Arena::new(&mut bytes);
    let bad = Reader::at(&input, off, input.len(), Limits::DNS)
        .unwrap()
        .name(&mut arena)
        .unwrap();
    let ff = name(b"\xff", &mut arena);
    let q = [
        Query {
            name: ff,
            kind: Type::A,
            class: 1,
        },
        Query {
            name: bad,
            kind: Type::A,
            class: 1,
        },
    ];
    let p = Packet::new([1, 2], 0, &q, &[], &[], &[]);
    let mut idna = Workspace::new();
    let backend = Backend::new(&mut idna, ILimits::GNUNET, PROFILE);
    let mut work = [0; 4096];
    let mut text = [0; 4096];
    let mut scratch = NativeScratch::new(&mut work, &mut text, Limits::DNS);
    let mut bytes = [0; 4096];
    let mut arena = Arena::new(&mut bytes);
    let mut qs = [Query::EMPTY; 2];
    let mut out = [0xa5; 512];
    assert_eq!(
        p.pack_native(
            NOW,
            &backend,
            &mut scratch,
            &mut arena,
            &mut qs,
            &mut [],
            &mut out,
            512
        ),
        Err(Error::Malformed)
    );
    assert_eq!(out, [0xa5; 512]);
}
#[test]
fn native_size_is_wire_size_not_conservative_builder_capacity() {
    let q = [Query {
        name: Name::ROOT,
        kind: Type::A,
        class: 1,
    }];
    let p = Packet::new([1, 2], 0, &q, &[], &[], &[]);
    let mut idna = Workspace::new();
    let backend = Backend::new(&mut idna, ILimits::GNUNET, PROFILE);
    for (cap, truncated, count) in [(17, true, 0), (18, false, 1)] {
        let mut work = [0; 255];
        let mut text = [0; 255];
        let mut scratch = NativeScratch::new(&mut work, &mut text, Limits::DNS);
        let mut bytes = [0; 255];
        let mut arena = Arena::new(&mut bytes);
        let mut qs = [Query::EMPTY; 1];
        let mut out = [0xa5; 512];
        let r = p
            .pack_native(
                NOW,
                &backend,
                &mut scratch,
                &mut arena,
                &mut qs,
                &mut [],
                &mut out,
                cap,
            )
            .unwrap();
        assert_eq!(r.native_size, Some(17));
        assert_eq!(r.truncated, truncated);
        assert_eq!(r.counts.queries, count);
    }
}
#[test]
fn soa_fixed_fields_follow_both_names_at_exact_c_capacity() {
    let root = Name::ROOT;
    let record = Record {
        name: root,
        kind: Type::SOA,
        class: 1,
        expiration: NOW,
        data: RData::Soa(Soa {
            mname: root,
            rname: root,
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum_ttl: 0,
        }),
    };
    let records = [record];
    let p = Packet::new([1, 2], 0, &[], &records, &[], &[]);
    let mut idna = Workspace::new();
    let backend = Backend::new(&mut idna, ILimits::GNUNET, PROFILE);
    for (cap, truncated, count) in [(44, true, 0), (45, false, 1), (46, false, 1)] {
        let mut work = [0; 255];
        let mut text = [0; 255];
        let mut scratch = NativeScratch::new(&mut work, &mut text, Limits::DNS);
        let mut bytes = [0; 255];
        let mut arena = Arena::new(&mut bytes);
        let mut rs = [Record::EMPTY; 1];
        let mut out = [0xa5; 512];
        let r = p
            .pack_native(
                NOW,
                &backend,
                &mut scratch,
                &mut arena,
                &mut [],
                &mut rs,
                &mut out,
                cap,
            )
            .unwrap();
        assert_eq!(r.native_size, Some(45));
        assert_eq!(r.truncated, truncated);
        assert_eq!(r.counts.answers, count);
    }
}
#[test]
fn complete_form_refuses_semantic_input_and_small_storage_before_destination_changes() {
    let mut source = [0; 255];
    let mut a = Arena::new(&mut source);
    let valid = name(b"abc", &mut a);
    let invalid = name(b"\xff", &mut a);
    let qs = [
        Query {
            name: valid,
            kind: Type::A,
            class: 1,
        },
        Query {
            name: invalid,
            kind: Type::A,
            class: 1,
        },
    ];
    let p = Packet::new([1, 2], 0, &qs, &[], &[], &[]);
    let mut idna = Workspace::new();
    let backend = Backend::new(&mut idna, ILimits::GNUNET, PROFILE);
    let mut work = [0; 255];
    let mut text = [0; 255];
    let mut scratch = NativeScratch::new(&mut work, &mut text, Limits::DNS);
    let mut bytes = [0xa5; 255];
    let mut arena = Arena::new(&mut bytes);
    let mut dest = [Query::EMPTY; 2];
    assert_eq!(
        p.native_builder_form(&backend, &mut scratch, &mut arena, &mut dest, &mut []),
        Err(Error::Malformed)
    );
    assert_eq!(arena.used(), 0);
    assert_eq!(dest, [Query::EMPTY; 2]);
    let p = Packet::new([1, 2], 0, &qs[..1], &[], &[], &[]);
    let mut bytes = [0xa5; 4];
    let mut arena = Arena::new(&mut bytes);
    assert_eq!(
        p.native_builder_form(&backend, &mut scratch, &mut arena, &mut dest, &mut []),
        Err(Error::Capacity)
    );
    assert_eq!(arena.used(), 0);
    assert_eq!(dest, [Query::EMPTY; 2]);
}
#[test]
fn native_uri_cstring_boundary_is_separate_from_raw_lossless_and_needs_no_utf8() {
    let mut idna = Workspace::new();
    let backend = Backend::new(&mut idna, ILimits::GNUNET, PROFILE);
    let mut work = [0; 255];
    let mut text = [0; 255];
    let mut scratch = NativeScratch::new(&mut work, &mut text, Limits::DNS);
    for (target, accepted) in [(&b"https://a\0hidden"[..], false), (&b"\xff"[..], true)] {
        let record = Record {
            name: Name::ROOT,
            kind: Type::URI,
            class: 1,
            expiration: NOW,
            data: RData::Uri(Uri {
                priority: 1,
                weight: 2,
                target,
            }),
        };
        let records = [record];
        let p = Packet::new([1, 2], 0, &[], &records, &[], &[]);
        let mut raw = [0; 512];
        let raw_len = p.encode(NOW, &mut raw).unwrap();
        assert!(raw_len > 12);
        let mut bytes = [0; 255];
        let mut arena = Arena::new(&mut bytes);
        let mut rs = [Record::EMPTY; 1];
        let mut out = [0xa5; 512];
        let result = p.pack_native(
            NOW,
            &backend,
            &mut scratch,
            &mut arena,
            &mut [],
            &mut rs,
            &mut out,
            512,
        );
        if accepted {
            assert!(!result.unwrap().truncated);
        } else {
            assert_eq!(result, Err(Error::InvalidInput));
            assert_eq!(out, [0xa5; 512]);
        }
    }
}
