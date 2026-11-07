//! Independent original normal C primitive/declaration and extracted path vectors.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions compare independently generated normal C bytes and negative signatures."
)]
use gnunet_crypto::{EddsaPrivateKey, hash512};
use gnunet_dht::{
    path,
    routing::{PeerBloom, peer_key},
};
use gnunet_types::Error;
use gnunet_wire::official::{
    AbsoluteTime,
    dht::{
        Path,
        ipc::{Request, RequestId},
    },
};
#[test]
fn normal_c_peer_hash_and_bloom_bits_are_exact() {
    let identity = core::array::from_fn(|i| i as u8);
    let key = peer_key(&identity);
    assert_eq!(&key, include_bytes!("fixtures/normal-c/peer-key.bin"));
    let mut filter = PeerBloom::empty();
    filter.insert_key(&key);
    assert_eq!(
        filter.as_bytes(),
        include_bytes!("fixtures/normal-c/peer-bloom.bin")
    );
}
#[test]
fn normal_c_local_opaque_id_and_wide_fields_remain_exact() -> Result<(), Error> {
    let id = RequestId([0x80, 1, 0xfe, 3, 0xdc, 5, 0xba, 7]);
    let get = include_bytes!("fixtures/normal-c/get.bin");
    let Request::Get(g) = Request::decode(get)? else {
        return Err(Error::InvalidInput);
    };
    assert_eq!(g.id, id);
    assert_eq!(g.options, 0x81234567);
    assert_eq!(g.replication, 0x89abcdef);
    assert_eq!(g.block_type, 8);
    let mut out = [0; 88];
    g.encode(&mut out)?;
    assert_eq!(&out, get);
    let put = include_bytes!("fixtures/normal-c/put.bin");
    let Request::Put(p) = Request::decode(put)? else {
        return Err(Error::InvalidInput);
    };
    assert_eq!(p.expiration, AbsoluteTime::from_micros(0x0102030405060708));
    p.encode(&mut out)?;
    assert_eq!(&out, put);
    let stop = include_bytes!("fixtures/normal-c/stop.bin");
    let Request::Stop(s) = Request::decode(stop)? else {
        return Err(Error::InvalidInput);
    };
    assert_eq!(s.id, id);
    let mut out = [0; 80];
    s.encode(&mut out)?;
    assert_eq!(&out, stop);
    let known = include_bytes!("fixtures/normal-c/known.bin");
    let Request::Known(k) = Request::decode(known)? else {
        return Err(Error::InvalidInput);
    };
    assert_eq!(k.id, id);
    assert_eq!(k.hashes.iter().count(), 0);
    k.encode(&mut out)?;
    assert_eq!(&out, known);
    let monitor = include_bytes!("fixtures/normal-c/monitor.bin");
    let Request::MonitorStart(m) = Request::decode(monitor)? else {
        return Err(Error::InvalidInput);
    };
    assert_eq!((m.get, m.get_response, m.put), (0x8001, 0x0102, 0xffff));
    m.encode(false, &mut out)?;
    assert_eq!(&out, monitor);
    Ok(())
}
#[test]
fn normal_c_full_signed_chain_and_original_region_verify_without_reinterpretation()
-> Result<(), Error> {
    let bytes = include_bytes!("fixtures/normal-c/path.bin");
    let payload = include_bytes!("fixtures/normal-c/payload.bin");
    let exp = 0x0102030405060708;
    let put = Path::new(&bytes[..96])?;
    let get = Path::new(&bytes[96..])?;
    assert_eq!(path::verify(payload, exp, None, put, get, &[4; 32]), Ok(()));
    let c = EddsaPrivateKey::from_seed([3; 32]);
    let b = EddsaPrivateKey::from_seed([2; 32]);
    let region = path::region(&hash512(payload), exp, b.public_key().as_bytes(), &[4; 32]);
    assert_eq!(&region, include_bytes!("fixtures/normal-c/last-region.bin"));
    assert_eq!(c.sign(6, &region)?.as_bytes(), &bytes[192..256]);
    path::verify_incoming(
        payload,
        exp,
        0,
        None,
        put,
        Path::new(&bytes[96..192])?,
        c.public_key().as_bytes(),
        &[4; 32],
        c.sign(6, &region)?.as_bytes(),
    )?;
    let mut invalid = *bytes;
    invalid[0] ^= 1;
    let error = path::verify(
        payload,
        exp,
        None,
        Path::new(&invalid[..96])?,
        Path::new(&invalid[96..])?,
        &[4; 32],
    )
    .err()
    .ok_or(Error::InvalidInput)?;
    assert_eq!(error.index, 0);
    let suffix = path::suffix(
        Path::new(&invalid[..96])?,
        Path::new(&invalid[96..])?,
        error,
    )?;
    assert_eq!(
        path::verify(
            payload,
            exp,
            Some(&suffix.truncated),
            suffix.put,
            suffix.get,
            &[4; 32]
        ),
        Ok(())
    );
    Ok(())
}
