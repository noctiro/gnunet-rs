//! Public DNS bytes only; no advertisement verification, hashes or native IO.
use crate::Error;
use crate::packet::{self, Address, AddressRecord, Families, Replacement, RewriteBuffers};
use gnunet_wire::official::dns::{Decision, Request};

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "This public-byte model reports assertion failures through the test harness while propagating parser errors."
)]
fn rewrites_all_record_sections_with_actual_lease_ttls_and_opaque_ids() -> Result<(), Error> {
    let mut input = [0u8; 62];
    input[..12].copy_from_slice(&[0x12, 0x34, 0x81, 0xa0, 0, 1, 0, 1, 0, 1, 0, 1]);
    input[12..17].copy_from_slice(&[0, 0, 1, 0, 1]);
    for (index, ttl) in [60, 50, 40].into_iter().enumerate() {
        let at = 17 + index * 15;
        input[at..at + 15].copy_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, ttl, 0, 4, 192, 0, 2, 1]);
    }
    let before = input;
    let limits = gnunet_dns::Limits::DNS;
    let families = Families {
        ipv4: true,
        ipv6: true,
    };
    let mut plan = [AddressRecord::EMPTY; 3];
    let mut a = [0; 1024];
    let mut b = [0; 1024];
    assert_eq!(
        packet::scan(&input, families, &mut plan, &mut a, limits)?,
        3
    );
    let replacements = [
        Replacement {
            address: Address::V4([198, 51, 100, 1]),
            lease_until: 31_000_000,
        },
        Replacement {
            address: Address::V4([198, 51, 100, 2]),
            lease_until: 1_500_000,
        },
        Replacement {
            address: Address::V4([198, 51, 100, 3]),
            lease_until: 101_000_000,
        },
    ];
    let mut output = [0; 62];
    assert_eq!(
        packet::rewrite(
            &input,
            &plan,
            &replacements,
            1_000_000,
            RewriteBuffers {
                output: &mut output,
                original: &mut a,
                transformed: &mut b,
            },
            limits
        )?,
        input.len()
    );
    assert_eq!(input, before);
    assert_eq!(output[3] & 0x20, 0);
    let mut transformed = [AddressRecord::EMPTY; 3];
    assert_eq!(
        packet::scan(&output, families, &mut transformed, &mut a, limits)?,
        3
    );
    for (index, ttl) in [30, 0, 40].into_iter().enumerate() {
        assert_eq!(transformed[index].ttl_seconds(), ttl);
        assert_eq!(transformed[index].address(), replacements[index].address);
    }
    let id = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
    let mut frame = [0; 78];
    let n = Request::Reply {
        id,
        decision: Decision::Answer(&output),
    }
    .encode(&mut frame)?;
    let Request::Reply {
        id: returned,
        decision: Decision::Answer(bytes),
    } = Request::decode(&frame[..n])?
    else {
        return Err(Error::Malformed);
    };
    assert_eq!(returned, id);
    assert_eq!(bytes, output);
    let mut uncached = [0; 62];
    assert_eq!(
        packet::rewrite_uncached(
            &input,
            &plan,
            &replacements,
            1_000_000,
            RewriteBuffers {
                output: &mut uncached,
                original: &mut a,
                transformed: &mut b
            },
            limits,
        )?,
        input.len()
    );
    assert_eq!(
        packet::scan(&uncached, families, &mut transformed, &mut a, limits)?,
        3
    );
    for (index, record) in transformed.iter().enumerate() {
        assert_eq!(record.ttl_seconds(), 0);
        assert_eq!(record.address(), replacements[index].address);
    }
    assert_eq!(input, before);
    assert_eq!(uncached[3] & 0x20, 0);
    Ok(())
}
