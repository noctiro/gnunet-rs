#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions check decoded public IPC words; decoder errors remain test errors"
)]
use super::{ConsumeFailure, ConsumeProfile, ConsumeStatus};
use gnunet_gnsrecord::{ZoneKey, ZoneKeyType};
use gnunet_reclaim::ipc;
use gnunet_types::Error;
use gnunet_wire::official::message_type;

fn decode_status(result_bytes: [u8; 4]) -> Result<u32, Error> {
    // Source-constructed public C layout: 20-byte packed prefix, then a
    // 36-byte typed public identity, and two empty serialized lists.
    // These synthetic public bytes establish no key authenticity.
    let mut frame = [0u8; 56];
    frame[..2].copy_from_slice(&56u16.to_be_bytes());
    frame[2..4].copy_from_slice(
        &message_type::RECLAIM_CONSUME_TICKET_RESULT
            .value()
            .to_be_bytes(),
    );
    frame[4..8].copy_from_slice(&19u32.to_be_bytes());
    frame[8..12].copy_from_slice(&result_bytes);
    frame[18..20].copy_from_slice(&36u16.to_be_bytes());
    frame[20..24].copy_from_slice(&65536u32.to_be_bytes());
    frame[24..].fill(0x42);
    match ipc::Response::decode(&frame)? {
        ipc::Response::Consumed {
            rid,
            result,
            reserved,
            identity,
            attributes,
            presentations,
        } => {
            assert_eq!(rid, 19);
            assert_eq!(reserved, 0);
            assert_eq!(identity, Some(ZoneKey::new(ZoneKeyType::Pkey, [0x42; 32])));
            assert!(attributes.is_empty());
            assert!(presentations.is_empty());
            Ok(result)
        }
        _ => Err(Error::Malformed),
    }
}

#[test]
fn canonical_profile_accepts_only_its_be32_success() -> Result<(), Error> {
    let raw = decode_status([0x00, 0x00, 0x00, 0x01])?;
    assert_eq!(raw, 1);
    assert!(ConsumeProfile::Canonical.classify(raw) == ConsumeStatus::Success);
    assert_eq!(
        ConsumeProfile::CNativeLittle.classify(raw),
        ConsumeStatus::Unknown
    );
    Ok(())
}

#[test]
fn c_little_profile_accepts_the_complete_u32_producer_word() -> Result<(), Error> {
    // Pinned C writes uint32_t result = htons(GNUNET_OK), where OK is 1.
    // Little-endian object representation is [00, 01, 00, 00].
    let raw = decode_status([0x00, 0x01, 0x00, 0x00])?;
    assert_eq!(raw, 0x0001_0000);
    assert!(ConsumeProfile::CNativeLittle.classify(raw) == ConsumeStatus::Success);
    assert_eq!(
        ConsumeProfile::Canonical.classify(raw),
        ConsumeStatus::Unknown
    );
    // This was the former, incorrect interpretation of the 32-bit field.
    let former = decode_status([0x00, 0x00, 0x01, 0x00])?;
    assert_eq!(former, 0x0000_0100);
    assert_eq!(
        ConsumeProfile::CNativeLittle.classify(former),
        ConsumeStatus::Unknown
    );
    Ok(())
}

#[test]
fn both_profiles_preserve_and_reject_failure_and_unknown_words() -> Result<(), Error> {
    // NO=0; canonical SYSERR=-1; C little-endian htons(-1) in u32;
    // plus an unrecognized nonzero word, which must not imply success.
    for (bytes, expected) in [
        ([0x00, 0x00, 0x00, 0x00], 0),
        ([0xff, 0xff, 0xff, 0xff], u32::MAX),
        ([0xff, 0xff, 0x00, 0x00], 0xffff_0000),
        ([0x00, 0x00, 0x00, 0x02], 2),
    ] {
        let raw = decode_status(bytes)?;
        assert_eq!(raw, expected);
        for profile in [ConsumeProfile::Canonical, ConsumeProfile::CNativeLittle] {
            assert_ne!(profile.classify(raw), ConsumeStatus::Success);
        }
    }
    assert_eq!(
        ConsumeProfile::Canonical.classify(u32::MAX),
        ConsumeStatus::Failed
    );
    assert_eq!(
        ConsumeProfile::CNativeLittle.classify(0xffff_0000),
        ConsumeStatus::Failed
    );
    assert_eq!(
        ConsumeProfile::Canonical.classify(0xffff_0000),
        ConsumeStatus::Unknown
    );
    assert_eq!(
        ConsumeProfile::CNativeLittle.classify(u32::MAX),
        ConsumeStatus::Unknown
    );
    assert_eq!(ConsumeProfile::Canonical.classify(0), ConsumeStatus::Denied);
    let issuer = ZoneKey::new(ZoneKeyType::Edkey, [0x42; 32]);
    assert!(matches!(
        ConsumeProfile::Canonical.validate(0, None, issuer),
        Err(crate::Error::Consume {
            raw: 0,
            cause: ConsumeFailure::IssuerMismatch
        })
    ));
    assert!(matches!(
        ConsumeProfile::Canonical.validate(
            1,
            Some(ZoneKey::new(ZoneKeyType::Edkey, [0x43; 32])),
            issuer
        ),
        Err(crate::Error::Consume {
            raw: 1,
            cause: ConsumeFailure::IssuerMismatch
        })
    ));
    Ok(())
}

#[test]
fn actual_unix_consume_failures_never_render_as_success_and_keep_the_raw_word()
-> Result<(), crate::test_support::Failure> {
    use crate::test_support::{Failure, Reply, Setup, header, request};
    use gnunet_rest::route::Endpoint;
    use std::{io::Write, time::Duration};
    tokio::runtime::Builder::new_current_thread().enable_all().build()?.block_on(async {
        for (profile, success, failed) in [(ConsumeProfile::Canonical, 1, u32::MAX), (ConsumeProfile::CNativeLittle, 0x0001_0000, 0xffff_0000)] {
            let setup = Setup::new()?;
            let identity = ZoneKey::new(ZoneKeyType::Edkey, [0x42; 32]);
            let raw = [success, 0, failed, 2, success];
            let mut replies: Vec<_> = raw[..4].iter().copied().map(Reply::Status).collect();
            replies.push(Reply::LargeAttribute(success));
            let peer = setup.peer(identity, replies)?;
            let outcome: Result<(), Failure> = async {
            let mut context = setup.context(profile, Duration::from_secs(2))?;
            let mut zone = [0; gnunet_gnsrecord::ZONE_TEXT_LEN];
            let zone = identity.write_ztld(&mut zone)?;
            let mut body = zeroize::Zeroizing::new(Vec::new());
            write!(&mut *body, "{{\"gns_name\":\"TEST.{zone}\",\"rp_uri\":\"urn:fixture\"}}")?;
            for (index, raw) in raw.into_iter().enumerate() {
                if index == 4 { context.limits.output_bytes = 64; }
                let result = context.execute(request("POST", "/reclaim/consume", &body, None)?).await;
                let response = match result {
                    Ok(response) if index == 0 => response,
                    Err(error @ crate::Error::Consume { .. }) if (1..4).contains(&index) => {
                        assert!(matches!(&error, crate::Error::Consume { cause, .. } if *cause == [ConsumeFailure::Denied, ConsumeFailure::Service, ConsumeFailure::Unknown][index-1]));
                        crate::http::error_response(&error, Some(Endpoint::Consume), 4096)?
                    }
                    Err(error @ crate::Error::ConsumeReply { .. }) if index == 4 => {
                        assert!(matches!(&error, crate::Error::ConsumeReply { raw: actual, original } if *actual == raw && matches!(original.as_ref(), crate::Error::Core(Error::Capacity))));
                        crate::http::error_response(&error, Some(Endpoint::Consume), 64)?
                    }
                    Err(error) => return Err(format!("consume case {index} returned {error}").into()),
                    Ok(response) => return Err(format!("consume case {index} unexpectedly returned HTTP {}", response.status).into()),
                };
                assert_eq!(response.status, [200, 403, 502, 502, 413][index]);
                assert_eq!(response.service_status, Some(i64::from(raw)));
                assert!(header(&response, b"WWW-Authenticate").is_none());
                if index != 0 { assert_eq!(header(&response, b"Cache-Control"), Some(b"no-store".as_slice())); }
            }
            Ok(())
            }.await;
            peer.finish(outcome)?;
        }
        Ok(())
    })
}

#[test]
fn actual_source_loss_and_original_timeout_remain_independent_of_ticket_denial()
-> Result<(), crate::test_support::Failure> {
    use crate::test_support::{Failure, Reply, Setup, header, request};
    use gnunet_rest::route::Endpoint;
    use std::{io::Write, time::Duration};
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let setup = Setup::new()?;
            let identity = ZoneKey::new(ZoneKeyType::Edkey, [0x43; 32]);
            let peer = setup.peer(identity, vec![Reply::Disconnect, Reply::NoResponse])?;
            let outcome: Result<(), Failure> = async {
                let context =
                    setup.context(ConsumeProfile::Canonical, Duration::from_millis(100))?;
                let mut zone = [0; gnunet_gnsrecord::ZONE_TEXT_LEN];
                let zone = identity.write_ztld(&mut zone)?;
                let mut body = zeroize::Zeroizing::new(Vec::new());
                write!(
                    &mut *body,
                    "{{\"gns_name\":\"TEST.{zone}\",\"rp_uri\":\"urn:fixture\"}}"
                )?;
                for index in 0..2 {
                    let error = context
                        .execute(request("POST", "/reclaim/consume", &body, None)?)
                        .await
                        .err()
                        .ok_or("consume unexpectedly succeeded")?;
                    if index == 0 && !matches!(&error, crate::Error::ReclaimSource(_)) {
                        return Err(format!("source loss case {index} returned {error}").into());
                    }
                    if index == 1 && !matches!(&error, crate::Error::Deadline) {
                        return Err(format!("original timeout returned {error}").into());
                    }
                    let response =
                        crate::http::error_response(&error, Some(Endpoint::Consume), 4096)?;
                    assert_eq!(response.status, if index == 0 { 502 } else { 504 });
                    assert_eq!(response.service_status, None);
                    assert!(header(&response, b"WWW-Authenticate").is_none());
                }
                Ok(())
            }
            .await;
            peer.finish(outcome)?;
            Ok(())
        })
}
