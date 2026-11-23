//! Public DNS payload and actual IP/UDP/helper envelope boundaries.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Public codec regressions assert original bytes, checksums and atomic resource refusal"
)]
use gnunet_dns_service_host::{core, packet};
use gnunet_types::Error;
use gnunet_vpn::packet::{Packet, UDP};
use packet::{Address, Framing};

const QUERY: [u8; 12] = [0x12, 0x34, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0];

fn endpoints() -> [(Address, Address, usize); 2] {
    [
        (
            Address::V4([192, 0, 2, 1]),
            Address::V4([192, 0, 2, 53]),
            20,
        ),
        (
            Address::V6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
            Address::V6([0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53]),
            40,
        ),
    ]
}

fn query_packet(source: Address, destination: Address) -> Result<Vec<u8>, Error> {
    let mut udp = [0; 8];
    udp[..2].copy_from_slice(&5555u16.to_be_bytes());
    udp[2..4].copy_from_slice(&53u16.to_be_bytes());
    let mut bytes = vec![0; 128];
    let count =
        gnunet_vpn::packet::build_parts(source, destination, UDP, &udp, &QUERY, &mut bytes)?;
    bytes.truncate(count);
    Ok(bytes)
}

#[test]
fn helper_and_native_envelopes_keep_one_borrowed_dns_body_and_exact_reply() -> Result<(), Error> {
    for (source, destination, header) in endpoints() {
        let raw = query_packet(source, destination)?;
        let (native_query, native_tuple) = packet::decode_query(&raw)?;
        assert_eq!(native_query.bytes(), &QUERY);
        assert_eq!(native_query.bytes().as_ptr(), raw[header + 8..].as_ptr());

        let mut helper = vec![0; raw.len() + packet::HELPER_PREFIX];
        let count = packet::encode_helper(&raw, &mut helper)?;
        let before = helper.clone();
        let (helper_query, helper_tuple) = packet::decode_helper_query(&helper[..count])?;
        assert_eq!(helper_query.bytes(), native_query.bytes());
        assert_eq!(helper_tuple, native_tuple);
        assert_eq!(
            helper_query.bytes().as_ptr(),
            helper[packet::HELPER_PREFIX + header + 8..].as_ptr(),
        );

        let mut answer = QUERY;
        answer[2] |= 0x80;
        for framing in [Framing::Raw, Framing::Helper] {
            let mut output = vec![0; helper_tuple.encoded_len(answer.len(), framing)?];
            let count = helper_tuple.encode(&answer, framing, &mut output)?;
            let reply = match framing {
                Framing::Raw => &output[..count],
                Framing::Helper => packet::helper_packet(&output[..count])?,
            };
            let checked = Packet::parse(reply)?;
            checked.validate_checksums()?;
            assert_eq!(checked.source(), destination);
            assert_eq!(checked.destination(), source);
            assert_eq!(checked.ports()?, (53, 5555));
            assert_eq!(&checked.segment()[8..], &answer);
        }
        assert_eq!(
            helper, before,
            "reply construction changed the captured query"
        );
    }
    Ok(())
}

#[test]
fn host_envelope_limits_remain_separate_from_dns_ipc_limits() -> Result<(), Error> {
    for (source, destination, header) in endpoints() {
        let raw = query_packet(source, destination)?;
        let (_, tuple) = packet::decode_query(&raw)?;
        let ceiling = usize::from(u16::MAX) - packet::HELPER_PREFIX - header - 8;
        assert_eq!(tuple.encoded_len(ceiling, Framing::Helper)?, 65535);
        let mut larger_dns = vec![0; ceiling + 1];
        larger_dns[..QUERY.len()].copy_from_slice(&QUERY);
        assert!(core::Query::decode(&larger_dns).is_ok());

        let mut output = vec![0xa5; 65536];
        let before = output.clone();
        assert_eq!(
            tuple.encode(&larger_dns, Framing::Helper, &mut output),
            Err(Error::TooLarge),
        );
        assert_eq!(output, before, "size refusal modified the output");

        let mut short = vec![0xa5; tuple.encoded_len(QUERY.len(), Framing::Helper)? - 1];
        let before = short.clone();
        assert_eq!(
            tuple.encode(&QUERY, Framing::Helper, &mut short),
            Err(Error::Capacity),
        );
        assert_eq!(short, before, "capacity refusal modified the output");
    }
    Ok(())
}
