//! One public pure boundary model. No socket, hashing, key or crypto operation.
use gnunet_unix_communicator as unix;
use gnunet_wire::official::{MessageHeader, MessageType, communicator as ipc};

#[test]
#[expect(
    clippy::unwrap_used,
    reason = "One bounded public pure framing/encapsulation model uses checked literal mock identifiers, never keys or native operations"
)]
fn real_encapsulation_limits_and_opaque_callbacks() {
    let sender = [0x22; 32]; // Public mock identifier, never a secret/key import.
    let message = [0, 4, 0, 7];
    // C's no-prefix communicator registration is exactly the fixed struct:
    // header4, characteristics4, can_burst4, and no terminating string byte.
    let mut receive_only = [0xa5; 12];
    ipc::Request::Register {
        characteristics: ipc::Characteristics::Reliable,
        can_burst: false,
        prefix: b"",
    }
    .encode(&mut receive_only)
    .unwrap();
    assert_eq!(receive_only, [0, 12, 4, 187, 0, 0, 0, 1, 0, 0, 0, 0]);
    assert!(matches!(
        gnunet_transport::communicator::Request::decode(&receive_only).unwrap(),
        gnunet_transport::communicator::Request::Register { prefix: [], .. }
    ));
    assert!(matches!(
        ipc::Request::decode(&receive_only).unwrap(),
        ipc::Request::Register { prefix: [], .. }
    ));
    // The official native producer copies char path bytes, including non-UTF8
    // POSIX filenames. Its receiving Rust service must preserve those bytes.
    let raw_address = b"unix-/tmp/\xff";
    let mut add = [0; 64];
    let n = ipc::Request::AddAddress {
        id: 1,
        validity: 1,
        network: unix::NETWORK_LOOPBACK,
        address: raw_address,
    }
    .encode(&mut add)
    .unwrap();
    assert!(matches!(
        gnunet_transport::communicator::Request::decode(&add[..n]).unwrap(),
        gnunet_transport::communicator::Request::AddAddress { address, .. }
            if address == raw_address
    ));
    let mtu = unix::payload_mtu(65535).unwrap();
    assert_eq!(mtu, 65447);
    assert_eq!(unix::payload_mtu(2048).unwrap(), 2012);
    let mut packet = [0xaa; 64];
    assert_eq!(
        unix::encode(sender, &message, mtu, &mut packet).unwrap(),
        40
    );
    assert_eq!(&packet[..4], &[0, 40, 0, 0]);
    packet[2..4].copy_from_slice(&0x7fffu16.to_be_bytes());
    packet[40..42].copy_from_slice(&[0xfe, 0xfd]);
    let decoded = unix::Datagram::decode(&packet[..42], mtu).unwrap();
    assert_eq!(decoded.claimed_sender, sender);
    assert_eq!(decoded.message, &message);
    assert_eq!(decoded.trailing, &[0xfe, 0xfd]);
    assert_eq!(decoded.outer_type, 0x7fff);
    let before = [0xa5; 39];
    let mut small = before;
    assert!(unix::encode(sender, &message, mtu, &mut small).is_err());
    assert_eq!(small, before);
    let mut incoming = vec![0; 65535];
    let mut maximum = vec![0; mtu];
    MessageHeader::from_total_size(MessageType::new(7), mtu)
        .unwrap()
        .encode(&mut maximum)
        .unwrap();
    let flow = [0x88; 8];
    let request = ipc::Request::Incoming {
        flow_control: true,
        flow_id: flow,
        validity: u64::MAX,
        peer: sender,
        neighbour: [0; 32],
        message: &maximum,
    };
    assert_eq!(request.encoded_len().unwrap(), 65535);
    assert_eq!(request.encode(&mut incoming).unwrap(), 65535);
    assert!(
        matches!(gnunet_transport::communicator::Request::decode(&incoming).unwrap(),gnunet_transport::communicator::Request::Incoming{peer,message,..}if peer.0==sender&&message.len()==mtu)
    );
    assert!(
        matches!(ipc::Request::decode(&incoming).unwrap(),ipc::Request::Incoming{flow_id,..}if flow_id==flow)
    );
    let mut too_big = vec![0; mtu + 1];
    let size = too_big.len();
    MessageHeader::from_total_size(MessageType::new(7), size)
        .unwrap()
        .encode(&mut too_big)
        .unwrap();
    let oversized = ipc::Request::Incoming {
        flow_control: true,
        flow_id: flow,
        validity: 1,
        peer: sender,
        neighbour: [0; 32],
        message: &too_big,
    };
    assert!(oversized.encoded_len().is_err());
    let mut result = [0; 52];
    let mid = [9, 8, 7, 6, 5, 4, 3, 2];
    ipc::Request::Sent {
        message_id: mid,
        queue: 0x01020304,
        peer: sender,
        status: -1,
    }
    .encode(&mut result)
    .unwrap();
    assert_eq!(&result[4..8], &u32::MAX.to_be_bytes());
    assert_eq!(&result[8..16], &mid);
    assert!(
        matches!(ipc::Request::decode(&result).unwrap(),ipc::Request::Sent{status:-1,queue:0x01020304,message_id,..}if message_id==mid)
    );
    let address = unix::Address::decode(b"unix-@public-test").unwrap();
    assert!(address.is_abstract());
    assert!(address.check_capacity(108).is_ok());
    let mut bytes = [0; 32];
    let n = address.encode(&mut bytes).unwrap();
    assert_eq!(&bytes[..n], b"unix-@public-test");
}
