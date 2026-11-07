//! One source-only aggregate model using PUBLIC NONSECRET mock bytes. These are
//! not curve keys/JWT/PABC proofs and no crypto, store, service, MQ or DHT runs here.
use gnunet_gnsrecord::{ZoneKey, ZoneKeyType};
use gnunet_reclaim::{
    Attribute, AttributeList, AttributeType, Credential, CredentialList, CredentialType,
    Identifier, ListLimits, Name, Presentation, PresentationList, Sensitive, Ticket, Uri,
    ipc::{Callback, Iteration, Request, Response},
    sequence,
};
use gnunet_types::Error;
use gnunet_wire::official::{RelativeTime, identity::SecretKeyView};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assertions are this one public mock model's observations"
)]
fn active_objects_frames_lists_and_local_cancel() -> Result<(), Error> {
    let attribute = Attribute {
        kind: AttributeType::STRING,
        flags: 0x01020304,
        id: Identifier::new([3; 32]),
        credential: Identifier::new([4; 32]),
        name: Name::new(b"eMail")?,
        reserved: [0x1122, 0x3344],
        value: Sensitive::new(b"public@example.invalid\0"),
    };
    let credential = Credential::new(
        Identifier::new([4; 32]),
        CredentialType::JWT,
        Name::new(b"token")?,
        Sensitive::new(b"PUBLIC-MOCK-NOT-A-JWT\0"),
    );
    let presentation = Presentation {
        kind: CredentialType::new(0x01020304),
        credential: Identifier::new([4; 32]),
        ignored_flags: 0x12131415,
        ignored_words: [0x2122, 0x3132, 0x4142],
        value: Sensitive::new(b"PUBLIC-MOCK-NOT-A-PROOF"),
    };
    let mut ab = [0; 256];
    let an = attribute.encode(&mut ab)?;
    assert_eq!(an, 80 + 5 + b"public@example.invalid\0".len());
    assert_eq!(&ab[..8], &[0, 0, 0, 1, 1, 2, 3, 4]);
    assert_eq!(&ab[72..80], &[0x11, 0x22, 0, 5, 0x33, 0x44, 0, 23]);
    let decoded = Attribute::decode(&ab[..an])?;
    assert_eq!(decoded.name.bytes(), b"eMail");
    assert_eq!(decoded.credential, Identifier::new([4; 32]));
    let mut small = [0xa5; 79];
    assert_eq!(attribute.encode(&mut small), Err(Error::Capacity));
    assert!(small.iter().all(|b| *b == 0xa5));
    let mut odd = ab;
    odd[81] = 0;
    let odd_attribute = Attribute::decode(&odd[..an])?;
    assert_eq!(odd_attribute.name.bytes(), b"e");
    assert_eq!(odd_attribute.name.wire_bytes(), b"e\0ail");
    let mut odd_out = [0; 256];
    assert_eq!(odd_attribute.encode(&mut odd_out)?, an);
    assert_eq!(&odd_out[..an], &odd[..an]);
    let mut cb = [0; 256];
    let cn = credential.encode(&mut cb)?;
    assert_eq!(&cb[40..48], &[0, 0, 0, 5, 0, 0, 0, 22]);
    assert_eq!(
        Credential::decode(&cb[..cn])?.value.expose(),
        b"PUBLIC-MOCK-NOT-A-JWT\0"
    );
    let mut pb = [0; 256];
    let pn = presentation.encode(&mut pb)?;
    assert_eq!(pn, 48 + b"PUBLIC-MOCK-NOT-A-PROOF".len());
    assert_eq!(
        Presentation::decode(&pb[..pn])?.ignored_words,
        [0x2122, 0x3132, 0x4142]
    );
    let mut round = [0; 256];
    Presentation::decode(&pb[..pn])?.encode(&mut round)?;
    assert_eq!(&round[..pn], &pb[..pn]);
    let attrs = AttributeList::new(&ab[..an], ListLimits::IPC)?;
    let pres = PresentationList::new(&pb[..pn], ListLimits::IPC)?;
    let creds = CredentialList::new(&cb[..cn], ListLimits::IPC)?;
    assert_eq!(attrs.len(), 1);
    assert_eq!(creds.iter().count(), 1);
    assert_eq!(pres.iter().count(), 1);
    assert_eq!(
        attrs.iter().next().ok_or(Error::NotFound)?.value.expose(),
        attribute.value.expose()
    );
    assert!(AttributeList::new(&ab[..an - 1], ListLimits::IPC).is_err());
    assert!(
        AttributeList::new(
            &ab[..an],
            ListLimits {
                bytes: an,
                items: 0
            }
        )
        .is_err()
    );
    assert!(
        AttributeList::new(
            &ab[..an],
            ListLimits {
                bytes: an - 1,
                items: 1
            }
        )
        .is_err()
    );
    let mut list_out = [0; 512];
    let list_n = sequence::encode(&[attribute, attribute], ListLimits::IPC, &mut list_out)?;
    assert_eq!(
        AttributeList::new(&list_out[..list_n], ListLimits::IPC)?.len(),
        2
    );
    // Literal public mock value, only structural BE type+32-byte key parsing.
    // No key generation, import provider, signature, or private-file access.
    let mut mock_key = [0x55; 36];
    mock_key[..4].copy_from_slice(&65556_u32.to_be_bytes());
    let key = SecretKeyView::new(&mock_key)?;
    let ticket = Ticket::new(b"PUBLIC-MOCK-TICKET.example.invalid")?;
    let uri = Uri::new(b"urn:example:public-mock")?;
    let exp = RelativeTime::from_micros(0x0102030405060708);
    let fixed = [
        Request::StoreAttribute {
            rid: 0x12345678,
            expiration: exp,
            key,
            attribute,
        },
        Request::StoreCredential {
            rid: 1,
            expiration: RelativeTime::FOREVER,
            key,
            credential,
        },
        Request::DeleteAttribute {
            rid: 2,
            key,
            attribute,
        },
        Request::DeleteCredential {
            rid: 3,
            key,
            credential,
        },
        Request::IssueTicket {
            rid: 4,
            key,
            uri,
            attributes: attrs,
            reserved: 0x1234,
        },
        Request::RevokeTicket {
            rid: 5,
            key,
            ticket,
        },
        Request::ConsumeTicket {
            rid: 6,
            ticket,
            uri,
        },
    ];
    for request in fixed {
        let mut frame = [0; 1024];
        let n = request.encode(&mut frame)?;
        let parsed = Request::decode(&frame[..n])?;
        assert_eq!(parsed.request_id(), request.request_id());
        let mut reencoded = [0; 1024];
        assert_eq!(parsed.encode(&mut reencoded)?, n);
        assert_eq!(&reencoded[..n], &frame[..n]);
        assert!(Request::decode(&frame[..n - 1]).is_err());
        if request.request_id() == 0x12345678 {
            assert_eq!(&frame[2..4], &961_u16.to_be_bytes());
            assert_eq!(&frame[4..12], &[1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(&frame[12..16], &[0x12, 0x34, 0x56, 0x78]);
            assert_eq!(&frame[18..20], &[0, 36]);
            assert_eq!(&frame[20..56], &mock_key);
        }
    }
    for (kind, codes) in [
        (Iteration::Attributes, [963_u16, 965, 964]),
        (Iteration::Credentials, [980, 982, 981]),
        (Iteration::Tickets, [973, 975, 974]),
    ] {
        for (request, code) in [
            (
                Request::IterateStart {
                    kind,
                    rid: 0x11223344,
                    key,
                    reserved: 0x4321,
                },
                codes[0],
            ),
            (
                Request::IterateNext {
                    kind,
                    rid: 0x11223344,
                },
                codes[1],
            ),
            (
                Request::IterateStop {
                    kind,
                    rid: 0x11223344,
                },
                codes[2],
            ),
        ] {
            let mut frame = [0; 128];
            let n = request.encode(&mut frame)?;
            assert_eq!(&frame[2..4], &code.to_be_bytes());
            assert_eq!(Request::decode(&frame[..n])?.request_id(), 0x11223344);
            assert_eq!(n, if code == codes[0] { 48 } else { 8 });
        }
    }
    let identity = ZoneKey::new(ZoneKeyType::Edkey, [0x66; 32]);
    let responses = [
        Response::Success { rid: 1, result: 1 },
        Response::Success { rid: 2, result: -1 },
        Response::Attribute {
            rid: 3,
            reserved: 0x1234,
            credential_len: 0xabcd,
            identity: Some(identity),
            attribute: Some(attribute),
        },
        Response::Attribute {
            rid: 3,
            reserved: 0,
            credential_len: 0,
            identity: None,
            attribute: None,
        },
        Response::Credential {
            rid: 4,
            identity: Some(identity),
            credential: Some(credential),
        },
        Response::Credential {
            rid: 4,
            identity: None,
            credential: None,
        },
        Response::Ticket {
            rid: 5,
            ticket: Some(ticket),
            uri: Some(uri),
            presentations: pres,
        },
        Response::Ticket {
            rid: 5,
            ticket: None,
            uri: None,
            presentations: PresentationList::empty(),
        },
        Response::Revoked {
            rid: 6,
            result: 0xffffffff,
        },
        Response::Consumed {
            rid: 7,
            result: 0x100,
            reserved: 0x1234,
            identity: Some(identity),
            attributes: attrs,
            presentations: pres,
        },
    ];
    for response in responses {
        let mut frame = [0; 1024];
        let n = response.encode(&mut frame)?;
        let parsed = Response::decode(&frame[..n])?;
        assert_eq!(parsed.request_id(), response.request_id());
        let mut again = [0; 1024];
        assert_eq!(parsed.encode(&mut again)?, n);
        assert_eq!(&frame[..n], &again[..n]);
        if let Response::Consumed { result, .. } = parsed {
            assert_eq!(result, 0x100);
        }
    }
    let mut callback = Callback::new(44);
    assert!(callback.accepts(44));
    assert!(!callback.accepts(45));
    assert!(callback.cancel());
    assert!(!callback.cancel());
    assert!(!callback.accepts(44));
    // Suppression has no frame encoder and does not claim to cancel service work.
    assert!(Name::new(b"a\0b").is_err());
    assert!(Ticket::new(&[b'x'; 128]).is_err());
    assert!(Uri::new(&[b'x'; 256]).is_err());
    assert_eq!(Ticket::decode(b"x\0junk\0").err(), Some(Error::Malformed));
    // No-alloc format parsing only, using both official typed public-key tags.
    // Dots in the borrowed label and original label bytes remain untouched.
    for kind in [ZoneKeyType::Pkey, ZoneKeyType::Edkey] {
        let issuer = ZoneKey::new(kind, [0x42; 32]);
        let mut zone = [0; gnunet_gnsrecord::ZONE_TEXT_LEN];
        let zone = issuer.write_ztld(&mut zone)?;
        let mut name = [0; 128];
        let label = b"GROUP.ITEM";
        name[..label.len()].copy_from_slice(label);
        name[label.len()] = b'.';
        let length = label.len() + 1 + zone.len();
        name[label.len() + 1..length].copy_from_slice(zone.as_bytes());
        let ticket = Ticket::new(&name[..length])?;
        let (actual, zone) = ticket.capability()?;
        assert_eq!(actual, label);
        assert_eq!(actual.as_ptr(), name.as_ptr());
        assert_eq!(zone, issuer);
        assert_eq!(
            Ticket::new(&name[label.len()..length])?.capability(),
            Err(Error::Malformed)
        );
        name[length - 1] = 0xff;
        assert_eq!(
            Ticket::new(&name[..length])?.capability(),
            Err(Error::Malformed)
        );
    }
    assert!(Ticket::new(b"no-separator")?.capability().is_err());
    assert!(Ticket::new(b"label.invalid")?.capability().is_err());
    #[cfg(feature = "alloc")]
    {
        use gnunet_reclaim::owned::{Kind, Limits, Pool};
        let pool = Pool::new(Limits {
            objects: 1,
            bytes: 4096,
            object_bytes: 1024,
        })?;
        let initial = pool.usage();
        let stored = pool.attribute(attribute)?;
        assert_eq!(stored.attribute()?.value.expose(), attribute.value.expose());
        assert_eq!(pool.usage().objects, 1);
        assert!(pool.credential(credential).is_err());
        assert!(!format!("{stored:?}").contains("public@example"));
        assert!(stored.request().is_err());
        drop(stored);
        assert_eq!(pool.usage(), initial);
        let restored = pool.copy(Kind::Presentation, &pb[..pn])?;
        drop(pool);
        assert_eq!(
            restored.presentation()?.value.expose(),
            presentation.value.expose()
        );
        // The remaining owner keeps its original budget/zeroizing allocation.
    }
    Ok(())
}
