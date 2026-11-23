use super::*;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare exact nested Linux UAPI fields after fallible parsing"
)]
fn source_network_rule_is_encoded_in_one_batch() -> io::Result<()> {
    let wire = create_masquerade(38, Ipv4Addr::new(192, 0, 2, 200), Ipv4Prefix::new(25)?)?;
    let mut batch = wire.as_slice();
    let (header, body) = Header::take(&mut batch)?;
    assert_eq!((header.kind, body), (0x10, &[0, 0, 0, 10][..]));
    let (header, _) = Header::take(&mut batch)?;
    assert_eq!(header.kind, 0x0a00);
    let (header, _) = Header::take(&mut batch)?;
    assert_eq!(header.kind, 0x0a03);
    let (header, body) = Header::take(&mut batch)?;
    assert_eq!((header.kind, &body[..4]), (0x0a06, &[2, 0, 0, 0][..]));
    let mut rule = &body[4..];
    assert_eq!(take_attribute(&mut rule)?, (1, &b"nat\0"[..]));
    assert_eq!(take_attribute(&mut rule)?, (2, &b"postrouting\0"[..]));
    let (kind, mut expressions) = take_attribute(&mut rule)?;
    assert_eq!(kind, 0x8004);
    assert!(rule.is_empty());
    for name in [
        &b"payload\0"[..],
        b"bitwise\0",
        b"cmp\0",
        b"counter\0",
        b"masq\0",
    ] {
        let (kind, mut expression) = take_attribute(&mut expressions)?;
        assert_eq!(kind, 0x8001);
        assert_eq!(take_attribute(&mut expression)?, (1, name));
        let (kind, mut data) = take_attribute(&mut expression)?;
        assert_eq!(kind, 0x8002);
        if name == b"bitwise\0" {
            for _ in 0..3 {
                let _field = take_attribute(&mut data)?;
            }
            let (kind, mut mask) = take_attribute(&mut data)?;
            assert_eq!(kind, 0x8004);
            assert_eq!(take_attribute(&mut mask)?, (1, &[255, 255, 255, 128][..]));
        } else if name == b"cmp\0" {
            for _ in 0..2 {
                let _field = take_attribute(&mut data)?;
            }
            let (kind, mut network) = take_attribute(&mut data)?;
            assert_eq!(kind, 0x8003);
            assert_eq!(take_attribute(&mut network)?, (1, &[192, 0, 2, 128][..]));
        }
    }
    assert!(expressions.is_empty());
    let (header, body) = Header::take(&mut batch)?;
    assert_eq!((header.kind, body), (0x11, &[0, 0, 0, 10][..]));
    assert!(batch.is_empty());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Assertions verify forged and native ACK statuses after fallible encoding"
)]
fn transaction_acknowledgements_are_source_and_operation_specific() -> io::Result<()> {
    let mut transaction = BatchAck::new(38);
    let valid_reply = ack_reply(38, CREATE_TABLE, 0)?;
    transaction.accept(&valid_reply)?;
    assert!(!transaction.is_complete());
    assert_eq!(
        transaction
            .accept(&valid_reply)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );

    let wrong_port = ack_reply(39, CREATE_CHAIN, 0)?;
    assert_eq!(
        transaction
            .accept(&wrong_port)
            .err()
            .map(|error| error.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    let rejected_batch = ack_reply(38, BEGIN, -libc::EOPNOTSUPP)?;
    assert_eq!(
        transaction
            .accept(&rejected_batch)
            .err()
            .and_then(|error| error.raw_os_error()),
        Some(libc::EOPNOTSUPP)
    );
    for request in [CREATE_CHAIN, CREATE_RULE] {
        transaction.accept(&ack_reply(38, request, 0)?)?;
    }
    assert!(transaction.is_complete());
    Ok(())
}

fn ack_reply(port: u32, request: Request, status: i32) -> io::Result<[u8; 36]> {
    let mut output = [0; 36];
    Header {
        length: 36,
        kind: libc::NLMSG_ERROR as u16,
        flags: 0,
        sequence: request.sequence,
        port,
    }
    .write(&mut output)?;
    output[16..20].copy_from_slice(&status.to_ne_bytes());
    Header {
        length: 20,
        kind: request.kind,
        flags: request.flags,
        sequence: request.sequence,
        port,
    }
    .write(&mut output[20..])?;
    Ok(output)
}
