//! State-machine contracts with modeled allocation results, not native VPN leases.
use super::*;
use alloc::vec;
use gnunet_wire::official::dns::Decision;

mod pre;

const NOW: u64 = 1_000_000;
const UNTIL: u64 = 61_000_000;
const ID: [u8; 8] = [0x91, 0x32, 0x73, 0x24, 0x55, 0x16, 0x87, 0x48];
const FAMILIES: Families = Families {
    ipv4: true,
    ipv6: true,
};

fn addresses() -> [Address; 6] {
    let mut v6 = [0; 16];
    v6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
    let mut result = [Address::V4([0; 4]); 6];
    for ((index, entry), suffix) in result.iter_mut().enumerate().zip(1_u8..=6) {
        *entry = if index % 2 == 0 {
            Address::V4([192, 0, 2, suffix])
        } else {
            v6[15] = suffix;
            Address::V6(v6)
        };
    }
    result
}

fn response() -> Vec<u8> {
    // One root question; A and AAAA in each of the three record sections.
    let mut bytes = vec![
        0x12, 0x34, 0x81, 0xa0, 0, 1, 0, 2, 0, 2, 0, 2, 0, 0, 1, 0, 1,
    ];
    for address in addresses() {
        bytes.push(0);
        bytes.extend_from_slice(&address.kind().0.to_be_bytes());
        bytes.extend_from_slice(&1_u16.to_be_bytes());
        bytes.extend_from_slice(&120_u32.to_be_bytes());
        let width: u16 = match address {
            Address::V4(_) => 4,
            Address::V6(_) => 16,
        };
        bytes.extend_from_slice(&width.to_be_bytes());
        bytes.extend_from_slice(address.bytes());
    }
    bytes
}

fn limits(packet: usize, payload: usize) -> Limits {
    Limits {
        requests: 2,
        packet_bytes: packet,
        payload_bytes: payload,
        records: 6,
        ..Limits::default()
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Reject insufficient output capacity before any modeled VPN effect is observable"
)]
fn insufficient_reply_capacity_is_refused_before_vpn_allocation_work() -> Result<(), Error> {
    let packet = response();
    let instance = Instance::new();
    let mut core = Core::new(
        &instance,
        limits(packet.len(), 2 * packet.len() - 1),
        FAMILIES,
    )?;
    let source = core.attached(Stage::Post)?;
    assert_eq!(
        core.admit(source, ID, &packet, UNTIL, NOW),
        Err(Error::Capacity),
        "a selected address must not allocate a VPN lease without reply storage"
    );
    assert_eq!(core.pending(), 0);
    assert!(core.next_work(NOW)?.is_none());
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Exact-capacity dual-stack transformation keeps original jobs, bytes and callback identity"
)]
fn exact_reserved_capacity_completes_all_sections_and_releases_on_original_write()
-> Result<(), Error> {
    let packet = response();
    let instance = Instance::new();
    let mut core = Core::new(&instance, limits(packet.len(), 2 * packet.len()), FAMILIES)?;
    let source = core.attached(Stage::Post)?;
    let request = core.admit(source, ID, &packet, UNTIL, NOW)?;
    for destination in addresses() {
        let Some(Work::Allocate {
            job,
            request: original,
            destination: actual,
            lease_until,
            expires,
        }) = core.next_work(NOW)?
        else {
            return Err(Error::Conflict);
        };
        assert_eq!(original, request);
        assert_eq!(actual, destination);
        assert_eq!((lease_until, expires), (UNTIL, UNTIL));
        let wrong = match destination {
            Address::V4(_) => Address::V6([0; 16]),
            Address::V6(_) => Address::V4([0; 4]),
        };
        assert_eq!(
            core.allocation(
                job,
                Some(Replacement {
                    address: wrong,
                    lease_until: UNTIL
                }),
                NOW
            ),
            Err(Error::Authentication)
        );
        let replacement = Replacement {
            address: translated(destination),
            lease_until: UNTIL,
        };
        core.allocation(job, Some(replacement), NOW)?;
        assert_eq!(
            core.allocation(job, Some(replacement), NOW),
            Err(Error::Stale)
        );
    }
    assert_eq!(
        core.reply_queued(request),
        Err(Error::Replay),
        "only a validated transformation can admit a reply write"
    );
    let Some(Work::Reply {
        request: original,
        source: bound,
        id,
        decision: Decision::Answer(bytes),
        ..
    }) = core.next_work(NOW)?
    else {
        return Err(Error::Conflict);
    };
    assert_eq!((original, bound, id), (request, source, ID));
    assert_eq!(&bytes[..2], &packet[..2]);
    assert_eq!(
        bytes[3] & 0x20,
        0,
        "rewritten data has no original AD claim"
    );
    let mut records = [AddressRecord::EMPTY; 6];
    let mut scratch = [0; 2048];
    assert_eq!(
        packet::scan(
            bytes,
            FAMILIES,
            &mut records,
            &mut scratch,
            Limits::default().dns()
        )?,
        6
    );
    for (record, original) in records.iter().zip(addresses()) {
        assert_eq!(record.address(), translated(original));
        assert_eq!(
            record.ttl_seconds(),
            0,
            "queued output cannot extend the VPN lease"
        );
    }
    core.reply_queued(request)?;
    assert_eq!(
        core.admit(source, [2; 8], &packet, UNTIL, NOW),
        Err(Error::Capacity)
    );
    core.reply_written(source, request)?;
    assert_eq!(core.pending(), 0);
    core.admit(source, [2; 8], &packet, UNTIL, NOW)?;
    Ok(())
}

fn translated(address: Address) -> Address {
    match address {
        Address::V4(mut bytes) => {
            bytes[0] = 10;
            Address::V4(bytes)
        }
        Address::V6(mut bytes) => {
            bytes[0] = 0xfd;
            Address::V6(bytes)
        }
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Compression into rewritten RDATA must drop before any answer can be queued"
)]
fn a_compression_alias_cannot_skip_final_output_validation() -> Result<(), Error> {
    let mut packet = vec![
        0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, 0, 0, 1, 0, 1,
    ];
    packet.extend_from_slice(&[0, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 1, b'x', 0, 0]);
    // The second owner aliases the first A record's original address bytes.
    packet.extend_from_slice(&[0xc0, 28, 0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 192, 0, 2, 2]);
    let instance = Instance::new();
    let mut core = Core::new(&instance, limits(packet.len(), 2 * packet.len()), FAMILIES)?;
    let source = core.attached(Stage::Post)?;
    let request = core.admit(source, ID, &packet, UNTIL, NOW)?;
    for suffix in [1, 2] {
        let Some(Work::Allocate { job, .. }) = core.next_work(NOW)? else {
            return Err(Error::Conflict);
        };
        core.allocation(
            job,
            Some(Replacement {
                address: Address::V4([10, 0, 0, suffix]),
                lease_until: UNTIL,
            }),
            NOW,
        )?;
    }
    assert_eq!(core.reply_queued(request), Err(Error::Replay));
    assert!(
        matches!(core.next_work(NOW)?, Some(Work::Reply { request: original, decision: Decision::Drop, .. }) if original == request)
    );
    core.reply_queued(request)?;
    core.reply_written(source, request)?;
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Source replacement must retire old allocation authority while releasing its reserved memory"
)]
fn source_replacement_reuses_storage_without_reusing_old_allocation_authority() -> Result<(), Error>
{
    let packet = response();
    let instance = Instance::new();
    let mut core = Core::new(&instance, limits(packet.len(), 2 * packet.len()), FAMILIES)?;
    let old = core.attached(Stage::Post)?;
    let old_request = core.admit(old, ID, &packet, UNTIL, NOW)?;
    let Some(Work::Allocate { job, .. }) = core.next_work(NOW)? else {
        return Err(Error::Conflict);
    };
    core.source_stopped(old)?;
    assert_eq!(core.pending(), 0);
    let fresh = core.attached(Stage::Post)?;
    let request = core.admit(fresh, ID, &packet, UNTIL, NOW)?;
    assert_ne!(fresh, old);
    assert_ne!(request, old_request);
    assert_eq!(core.allocation(job, None, NOW), Err(Error::Stale));
    let Some(Work::Allocate {
        job,
        request: actual,
        ..
    }) = core.next_work(NOW)?
    else {
        return Err(Error::Conflict);
    };
    assert_eq!(actual, request);
    core.allocation(job, None, NOW)?;
    assert!(
        matches!(core.next_work(NOW)?, Some(Work::Reply { request: actual, decision: Decision::Drop, .. }) if actual == request)
    );
    core.reply_queued(request)?;
    core.reply_written(fresh, request)?;
    assert_eq!(core.pending(), 0);
    Ok(())
}
