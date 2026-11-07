//! Native compressed-name text, packet-context and atomic-output regressions.
#![expect(
    clippy::unwrap_used,
    reason = "Reference regressions require successful prerequisite parsing or fail."
)]
#![expect(
    clippy::panic,
    reason = "An unexpected record variant fails this actual native CNAME witness."
)]
use gnunet_dns::{AbsoluteTime, Arena, Error, Limits, Name, RData, Reader};
use gnunet_idna::{Backend, Limits as IdnaLimits, NativeProfile, Workspace};
const PROFILE: NativeProfile = NativeProfile::Libunistring1_5Unicode18_0;
#[test]
fn one_output_buffer_refuses_capacities_atomically_then_reuses_successfully() {
    let packet = b"\x01x\xc0\x04\0";
    let mut storage = [0; 255];
    let mut arena = Arena::new(&mut storage);
    let mut reader = Reader::new(packet, Limits::DNS).unwrap();
    let name = reader.name(&mut arena).unwrap();
    let mut idna = Workspace::new();
    let backend = Backend::new(&mut idna, IdnaLimits::GNUNET, PROFILE);
    let mut output = [0xa5; 16];
    let mut work = [0; 16];
    for cap in 0..2 {
        assert_eq!(
            name.write_native_text(&backend, &mut work, &mut output[..cap]),
            Err(Error::Capacity)
        );
        assert_eq!(output, [0xa5; 16]);
    }
    for cap in 0..2 {
        assert_eq!(
            name.write_native_text(&backend, &mut work[..cap], &mut output),
            Err(Error::Capacity)
        );
        assert_eq!(output, [0xa5; 16]);
    }
    assert_eq!(
        name.write_native_text(&backend, &mut work, &mut output[..2]),
        Ok(2)
    );
    assert_eq!(&output[..2], b"x.");
    assert!(output[2..].iter().all(|b| *b == 0xa5));
}
#[test]
fn whole_packet_length_applies_after_pointer_even_with_local_rdata_end() {
    // 40 copies of U+20000 decode to160 UTF8 bytes. Local RDATA is a2-byte
    // compression pointer; the actual complete packet has200 bytes.
    let label = b"xn--j50iaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    assert_eq!(label.len(), 47);
    let mut packet = vec![0, 0, 5, 0, 1, 0, 0, 0, 0, 0, 2, 0xc0, 13];
    packet.push(label.len() as u8);
    packet.extend_from_slice(label);
    packet.push(0);
    packet.resize(200, 0);
    let mut data = [0; 1024];
    let mut arena = Arena::new(&mut data);
    let mut reader = Reader::new(&packet, Limits::DNS).unwrap();
    let record = reader.record(AbsoluteTime::UNIX_EPOCH, &mut arena).unwrap();
    assert_eq!(reader.position(), 13);
    let RData::Hostname(name) = record.data else {
        panic!("expected CNAME")
    };
    let mut idna = Workspace::new();
    let backend = Backend::new(&mut idna, IdnaLimits::GNUNET, PROFILE);
    let mut text = [0; 1024];
    let n = name
        .write_native_text(&backend, &mut [0; 1024], &mut text)
        .unwrap();
    assert_eq!(&text[..n], "\u{20000}".repeat(40).as_bytes());
    let mut data2 = [0; 1024];
    let mut arena2 = Arena::new(&mut data2);
    let mut local = Reader::at(&packet, 11, 13, Limits::DNS).unwrap();
    let name2 = local.name(&mut arena2).unwrap();
    assert_eq!(name, name2);
    assert_eq!(
        name2.write_native_text(&backend, &mut [0; 1024], &mut text),
        Ok(n)
    );
}
#[test]
fn duplicate_preserves_provenance_while_wire_encoding_reconstruction_canonicalizes_it() {
    let packet = b"\x01x\xc0\x04\0";
    let mut storage = [0; 255];
    let mut arena = Arena::new(&mut storage);
    let name = Reader::new(packet, Limits::DNS)
        .unwrap()
        .name(&mut arena)
        .unwrap();
    let mut duplicate_storage = [0; 255];
    let duplicate = name
        .duplicate_into(&mut Arena::new(&mut duplicate_storage))
        .unwrap();
    assert_eq!(name, duplicate);
    let mut wire = [0; 255];
    let n = name.encode(&mut wire).unwrap();
    let reconstructed = Name::from_wire(&wire[..n]).unwrap();
    assert_ne!(name, reconstructed);
    assert_eq!(name.wire(), reconstructed.wire());
    let mut idna = Workspace::new();
    let backend = Backend::new(&mut idna, IdnaLimits::GNUNET, PROFILE);
    let mut output = [0; 16];
    let mut work = [0; 16];
    assert_eq!(
        name.write_native_text(&backend, &mut work, &mut output),
        Ok(2)
    );
    assert_eq!(&output[..2], b"x.");
    assert_eq!(
        duplicate.write_native_text(&backend, &mut work, &mut output),
        Ok(2)
    );
    assert_eq!(
        reconstructed.write_native_text(&backend, &mut work, &mut output),
        Ok(1)
    );
    assert_eq!(&output[..1], b"x");
    let mut dotted = [0; 16];
    assert_eq!(name.write_dotted(&mut dotted), Ok(1));
    assert_eq!(&dotted[..1], b"x");
}
