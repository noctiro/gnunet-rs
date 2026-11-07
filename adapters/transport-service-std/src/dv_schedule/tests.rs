//! Scheduling metadata only: no fabricated Actor token, signature, write or ACK.
use super::{Fault, IdlePass, PlanCursor, SCHEDULE_CLASSES};

fn check(value: bool) -> Result<(), Fault> {
    if value { Ok(()) } else { Err(Fault::Conflict) }
}
struct Plan {
    original: u64,
    until: u64,
    selected: [u8; 3],
    next: usize,
    recipients: usize,
}
fn completed(original: u64) -> Plan {
    Plan {
        original,
        until: 1000,
        selected: [10, 20, 30],
        next: 0,
        recipients: 0,
    }
}

#[test]
fn continuous_new_completed_plans_cannot_displace_existing_fanout() -> Result<(), Fault> {
    let mut rows = vec![
        completed(1),
        Plan {
            recipients: 3,
            ..completed(2)
        },
        Plan {
            recipients: 3,
            ..completed(3)
        },
    ];
    let mut cursor = PlanCursor::default();
    let mut emitted = [0; 2];
    let mut arrival = 100;
    // Every removal is followed by another ready empty fanout, like sustained
    // local-return/MAX_HOPS LEARN work. An index-zero scheduler gets trapped in
    // those newly swapped tails and leaves the other original fanout untouched.
    for _ in 0..12 {
        let index = cursor.take(rows.len()).ok_or(Fault::NotReady)?;
        if rows[index].next == rows[index].recipients {
            let old_len = rows.len();
            rows.swap_remove(index);
            cursor.removed(index, old_len);
            rows.push(completed(arrival));
            arrival += 1;
        } else {
            let row = &mut rows[index];
            check(row.until == 1000 && row.selected == [10, 20, 30])?;
            let original = usize::try_from(row.original - 2).map_err(|_| Fault::Overflow)?;
            emitted[original] += 1;
            row.next += 1;
        }
    }
    check(emitted == [3, 3])
}

#[test]
fn external_removal_preserves_the_next_original_row_and_bounded_pass() -> Result<(), Fault> {
    let mut rows = vec![10, 20, 30, 40];
    let mut cursor = PlanCursor::default();
    for _ in 0..3 {
        let _index = cursor.take(rows.len()).ok_or(Fault::NotReady)?;
    }
    let old_len = rows.len();
    rows.swap_remove(0); // The original next tail40 moves to zero.
    cursor.removed(0, old_len);
    check(rows[cursor.take(rows.len()).ok_or(Fault::NotReady)?] == 40)?;
    let mut seen = Vec::new();
    for _ in 0..rows.len() {
        seen.push(rows[cursor.take(rows.len()).ok_or(Fault::NotReady)?]);
    }
    seen.sort_unstable();
    check(seen == [20, 30, 40])?;

    let mut rows = vec![10, 20, 30, 40];
    let mut cursor = PlanCursor::default();
    let _first = cursor.take(rows.len()).ok_or(Fault::NotReady)?;
    let old_len = rows.len();
    rows.swap_remove(1); // The next row20 retired; preserve old successor30.
    cursor.removed(1, old_len);
    check(rows[cursor.take(rows.len()).ok_or(Fault::NotReady)?] == 30)?;
    cursor.removed(0, 1);
    check(cursor.take(0).is_none() && cursor.take(1) == Some(0))
}

#[test]
fn quantum_one_registers_every_class_and_a_complete_idle_pass_stops_waking() -> Result<(), Fault> {
    let mut pass = IdlePass::default();
    let mut observed = Vec::new();
    for class in 0..SCHEDULE_CLASSES {
        // Later polls preserve the incomplete original pass.
        observed.push(class);
        let complete = pass.idle();
        check(complete == (class + 1 == SCHEDULE_CLASSES))?;
    }
    check(observed == [0, 1, 2, 3] && pass.complete())?;
    // Another child may keep the parent polling. Those calls neither create
    // a fresh Scheduler pass nor a chain of child self-wakes.
    for _ in 0..16 {
        check(!pass.idle() && pass.complete())?;
    }
    // Only an actual original timer/local/Actor transition invalidates old
    // idle observations and grants another finite complete scan.
    pass.progress();
    check(!pass.complete())?;
    for step in 0..SCHEDULE_CLASSES {
        let complete = pass.idle();
        check(complete == (step + 1 == SCHEDULE_CLASSES))?;
    }
    check(pass.complete())
}
