//! One bounded pure algorithm model; not an original-C or SETU service profile.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Published CRC, actual peel, source wire packing and estimator lifecycle are independently checked"
)]
use gnunet_setu::{
    ibf::{Cell, Decode, Ibf, Key, Order, crc32},
    strata::{ALL_CELLS, BUCKETS, Strata},
};
use gnunet_types::Error;
#[test]
fn actual_peel_packed_source_stride_and_nested_strata_lifecycle() -> Result<(), Error> {
    assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    let order = Order::Little;
    let a = Key(0x1122_3344_5566_7788);
    let b = Key(0x1020_3040_5060_7080);
    assert_eq!(a.salted(0), a);
    assert_eq!(a.salted(53).unsalted(53), a);
    let mut left_cells = [Cell::default(); 37];
    let mut right_cells = [Cell::default(); 37];
    let mut left = Ibf::clear(&mut left_cells, 3, order)?;
    let mut right = Ibf::clear(&mut right_cells, 3, order)?;
    left.insert(a)?;
    left.insert(b)?;
    left.remove(b)?;
    right.insert(b)?;
    left.subtract(&right)?;
    let mut positive = None;
    let mut negative = None;
    for _ in 0..4 {
        match left.peel()? {
            Decode::Item { key, side: 1 } => {
                assert_eq!(positive, None);
                positive = Some(key);
            }
            Decode::Item { key, side: -1 } => {
                assert_eq!(negative, None);
                negative = Some(key);
            }
            Decode::Empty => break,
            _ => return Err(Error::Malformed),
        }
    }
    assert_eq!(positive, Some(a));
    assert_eq!(negative, Some(b));
    assert!(left.is_empty());
    let mut cells = [
        Cell {
            count: 5,
            ..Cell::default()
        },
        Cell {
            count: 2,
            ..Cell::default()
        },
        Cell {
            count: 7,
            ..Cell::default()
        },
    ];
    let ibf = Ibf::from_cells(&mut cells, 3, order)?;
    let mut wire = [0xa5; 60];
    assert_eq!(ibf.encode_slice(0, 3, 3, &mut wire)?, 60);
    assert_eq!(&wire[36..38], &[0xab, 0x80]);
    assert!(wire[38..].iter().all(|byte| *byte == 0));
    wire[59] = 0x55; // actual reference end padding is ignored on receive
    let mut decoded_cells = [Cell::default(); 3];
    let mut decoded = Ibf::clear(&mut decoded_cells, 3, order)?;
    decoded.read_slice(0, 3, 3, &wire)?;
    assert_eq!(decoded.cells(), ibf.cells());

    let mut local_cells = vec![Cell::default(); ALL_CELLS];
    let mut local = Strata::clear(&mut local_cells, order)?;
    // Source inserts inside every trailing-one level. This key has exactly two
    // trailing-one layers under all eight byte rotations, so its source heuristic
    // counts2, not an authoritative one-element cardinality result.
    let key = Key(0x0303_0303_0303_0303);
    local.insert(key)?;
    let mut wire = vec![0; Strata::wire_len(1)?];
    assert_eq!(local.write_raw(1, &mut wire)?, 50560);
    let mut remote_cells = vec![Cell::default(); Strata::cell_count(1)?];
    let mut remote = Strata::view(&mut remote_cells, 1, order)?;
    remote.read_raw(1, &wire)?;
    let mut scratch = [Cell::default(); BUCKETS];
    let equal = remote.estimate_difference(&local, 1, &mut scratch)?;
    assert_eq!(
        (equal.positive, equal.negative, equal.extrapolated),
        (0, 0, false)
    );
    local.remove(key)?;
    assert!(local.cells().iter().all(|cell| *cell == Cell::default()));
    let estimate = remote.estimate_difference(&local, 1, &mut scratch)?;
    assert_eq!(
        (estimate.positive, estimate.negative, estimate.extrapolated),
        (2, 0, false)
    );
    Ok(())
}
