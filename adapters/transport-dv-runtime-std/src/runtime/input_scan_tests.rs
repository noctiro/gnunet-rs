//! Bounded metadata policy checks, not crypto, native IO or provider receipts.
use super::*;

fn check(condition: bool) -> Result<(), Protocol> {
    if condition {
        Ok(())
    } else {
        Err(Protocol::Conflict)
    }
}

#[test]
fn clipped_waiting_prefix_cannot_hide_a_later_ready_original() -> Result<(), Protocol> {
    let rows = [(1u8, false), (2, false), (3, false), (4, true)];
    for quantum in 1..=64 {
        let mut scan = InputScan::default();
        let mut observed = None;
        let mut turns = 0;
        while observed.is_none() {
            scan.begin(rows.len());
            let mut work = 0;
            for _ in 0..quantum.min(rows.len()) {
                let index = scan.take().ok_or(Protocol::NotFound)?;
                work += 1;
                let (token, ready) = rows.get(index).ok_or(Protocol::Stale)?;
                if *ready {
                    observed = Some(*token);
                    break;
                }
            }
            check(work <= quantum)?;
            turns += 1;
            if observed.is_none() {
                check(scan.pending())?;
            }
            check(turns <= rows.len())?;
        }
        check(observed == Some(4))?;
    }
    Ok(())
}

#[test]
fn all_pending_rows_finish_debt_and_repeated_polls_do_not_recreate_it() -> Result<(), Protocol> {
    for quantum in 1..=64 {
        let mut scan = InputScan::default();
        let count = 5;
        let mut turns = 0;
        loop {
            scan.begin(count);
            for _ in 0..quantum.min(count) {
                scan.take().ok_or(Protocol::NotFound)?;
            }
            turns += 1;
            check(turns <= count)?;
            if !scan.pending() {
                break;
            }
        }
        // These stand for unchanged blocked/terminal metadata on subsequent
        // caller polls. They still get bounded checks, without a new wake chain.
        for _ in 0..32 {
            scan.begin(count);
            for _ in 0..quantum.min(count) {
                scan.take().ok_or(Protocol::NotFound)?;
            }
            check(!scan.pending())?;
        }
    }
    Ok(())
}

fn collect(scan: &mut InputScan, rows: &[u8]) -> Result<Vec<u8>, Protocol> {
    let mut seen = Vec::new();
    while scan.pending() {
        let index = scan.take().ok_or(Protocol::NotFound)?;
        seen.push(*rows.get(index).ok_or(Protocol::Stale)?);
    }
    Ok(seen)
}

#[test]
fn append_revisits_the_new_token_without_replacing_originals() -> Result<(), Protocol> {
    let mut rows = vec![1, 2, 3];
    let mut scan = InputScan::default();
    scan.begin(rows.len());
    check(scan.take() == Some(0) && scan.take() == Some(1))?;
    rows.push(4);
    scan.changed(rows.len());
    check(collect(&mut scan, &rows)? == [3, 4, 1, 2] && !scan.pending())
}

#[test]
fn swap_removal_and_same_length_replacement_cannot_lose_a_moved_token() -> Result<(), Protocol> {
    let mut rows = vec![1, 2, 3];
    let mut scan = InputScan::default();
    scan.begin(rows.len());
    check(scan.take() == Some(0))?;
    rows.swap_remove(0); // Original3 moves behind the already-advanced cursor.
    scan.changed(rows.len());
    check(collect(&mut scan, &rows)? == [2, 3])?;
    rows.push(4);
    scan.changed(rows.len());
    check(scan.take() == Some(1))?;
    rows.swap_remove(0);
    scan.changed(rows.len());
    rows.push(5); // Same row count as before, different original token/layout.
    scan.changed(rows.len());
    check(collect(&mut scan, &rows)? == [4, 2, 5] && !scan.pending())
}

#[test]
fn real_capacity_release_retries_an_earlier_blocked_owner_once_per_pass() -> Result<(), Protocol> {
    let mut scan = InputScan::default();
    let rows = [1, 2, 3];
    scan.begin(rows.len());
    check(collect(&mut scan, &rows)? == rows && !scan.pending())?;
    // A zero-effect refusal supplies no changed() call and cannot prolong debt.
    for _ in 0..8 {
        scan.begin(rows.len());
        scan.take().ok_or(Protocol::NotFound)?;
        check(!scan.pending())?;
    }
    // An actual loan/output/provider release grants one new bounded full pass.
    scan.changed(rows.len());
    let observed = collect(&mut scan, &rows)?;
    check(observed.len() == rows.len() && observed.contains(&1) && !scan.pending())
}

#[test]
fn source_close_clears_debt_without_restarting_for_terminal_receipts() -> Result<(), Protocol> {
    let mut scan = InputScan::default();
    scan.changed(4);
    scan.take().ok_or(Protocol::NotFound)?;
    check(scan.pending())?;
    scan.stop();
    for _ in 0..8 {
        check(!scan.pending() && scan.take().is_none())?;
        // The closed Runtime keeps only external cleanup receipts; its change
        // hook uses stop(), never changed(retained_row_count).
        scan.stop();
    }
    Ok(())
}

#[test]
fn an_actual_clock_revision_invalidates_idle_observations_only_once() -> Result<(), Protocol> {
    let mut revision = 7;
    let mut scan = InputScan::default();
    scan.begin(3);
    while scan.pending() {
        scan.take().ok_or(Protocol::NotFound)?;
    }
    for _ in 0..16 {
        check(!clock_adjusted(&mut revision, 7) && !scan.pending())?;
    }
    if clock_adjusted(&mut revision, 8) {
        scan.changed(3);
    }
    check(scan.pending())?;
    while scan.pending() {
        scan.take().ok_or(Protocol::NotFound)?;
    }
    for _ in 0..16 {
        check(!clock_adjusted(&mut revision, 8) && !scan.pending())?;
    }
    Ok(())
}

#[test]
fn alarm_observes_old_ready_without_postponing_an_unfinished_target()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    let _entered = runtime.enter();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let now = Instant::now();
    let past = now - std::time::Duration::from_secs(1);
    let future = now + std::time::Duration::from_secs(3600);
    let later = now + std::time::Duration::from_secs(7200);
    let mut alarm = Some(Box::pin(tokio::time::sleep_until(past)));
    check(poll_input_alarm(&mut alarm, &mut cx, future))?;
    check(
        alarm
            .as_ref()
            .is_some_and(|timer| timer.deadline() == future),
    )?;
    for _ in 0..8 {
        check(!poll_input_alarm(&mut alarm, &mut cx, later))?;
        check(
            alarm
                .as_ref()
                .is_some_and(|timer| timer.deadline() == future),
        )?;
    }
    Ok(())
}

#[test]
fn alarm_consumes_a_new_ready_target_and_registers_new_earlier_bounds()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    let _entered = runtime.enter();
    let mut cx = Context::from_waker(std::task::Waker::noop());
    let now = Instant::now();
    let future = now + std::time::Duration::from_secs(7200);
    let earlier = now + std::time::Duration::from_secs(3600);
    let past = now - std::time::Duration::from_secs(1);
    let mut alarm = None;
    check(!poll_input_alarm(&mut alarm, &mut cx, future))?;
    check(!poll_input_alarm(&mut alarm, &mut cx, earlier))?;
    check(
        alarm
            .as_ref()
            .is_some_and(|timer| timer.deadline() == earlier),
    )?;
    // The old registration was Pending, but the newly proposed target is
    // already Ready. Its observation must not be discarded as registration.
    check(poll_input_alarm(&mut alarm, &mut cx, past))?;
    let mut completions = 0;
    if poll_input_alarm(&mut alarm, &mut cx, past) {
        completions += 1;
    }
    check(completions == 1)?;
    Ok(())
}

#[test]
fn external_retirement_parks_original_scan_debt_until_real_settlement() -> Result<(), Protocol> {
    let mut scan = InputScan::default();
    scan.changed(4);
    scan.take().ok_or(Protocol::NotFound)?;
    for _ in 0..16 {
        check(scan.pending() && !runnable_input_scan(scan.pending(), false, true))?;
    }
    // The same debt was retained; an actual output settlement invalidates its
    // old partial observations before the native barrier disappears.
    scan.changed(4);
    check(runnable_input_scan(scan.pending(), false, false))?;
    let rows = [1, 2, 3, 4];
    check(collect(&mut scan, &rows)?.len() == 4 && !scan.pending())?;
    check(!runnable_input_scan(true, true, false))
}
