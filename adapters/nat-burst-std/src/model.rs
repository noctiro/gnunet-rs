//! One public pure framing/readiness/allocation model. No I/O or crypto is used.
use crate::{
    Instance,
    wire::{BurstMessage, BurstSync, Endian},
};
use gnunet_types::Error;

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Pure public framing/readiness/allocation assertions with fallible setup and no native or cryptographic work"
)]
fn public_wire_and_original_allocation() -> Result<(), Error> {
    let sync = BurstSync {
        rtt_micros: 70_000,
        ready: 1,
    };
    let mut bytes = [0; 36];
    assert_eq!(sync.encode(Endian::Little, &mut bytes)?, 12);
    assert_eq!(&bytes[8..12], &[1, 0, 0, 0]);
    assert_eq!(BurstSync::decode(&bytes[..12], Endian::Little)?, sync);
    assert_eq!(sync.delay(70_000), Some(140_000));
    assert_eq!(BurstSync { ready: 0, ..sync }.delay(70_000), Some(280_000));
    assert_eq!(sync.delay(220_000), None);
    assert_eq!(sync.delay(u64::MAX), None);
    assert_eq!(
        BurstSync {
            rtt_micros: u64::MAX - 1,
            ready: 1
        }
        .delay(u64::MAX - 1),
        Some(u64::MAX)
    );
    let message = BurstMessage {
        peer: [0x35; 32],
        local_port: 10_001,
    };
    assert_eq!(message.encode(Endian::Big, &mut bytes)?, 36);
    assert_eq!(&bytes[32..], &[0, 0, 0x27, 0x11]);
    assert_eq!(BurstMessage::decode(&bytes, Endian::Big)?, message);
    assert!(BurstMessage::decode(&bytes[..35], Endian::Big).is_err());
    assert!(BurstMessage::decode(&[0; 37], Endian::Big).is_err());
    let domain = Instance::new();
    let old = domain.allocate()?;
    let next = domain.allocate()?;
    assert_ne!(old, next);
    let other = Instance::new();
    assert_ne!(old, other.allocate()?);
    Ok(())
}
