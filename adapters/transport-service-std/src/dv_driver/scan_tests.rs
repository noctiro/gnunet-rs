//! Local scheduling-policy regressions, not native IO or delivery receipts.
use super::*;

fn check(condition: bool) -> Result<(), Error> {
    if condition {
        Ok(())
    } else {
        Err(Error::Conflict)
    }
}

#[test]
fn working_and_learning_heads_cannot_hide_an_original_ready_input() -> Result<(), Error> {
    let states = [
        actor::InputProgress::Working,
        actor::InputProgress::LearnReady,
        actor::InputProgress::Retiring,
        actor::InputProgress::DeliveryReady,
    ];
    let mut cursor = 0;
    let mut visits = Vec::new();
    let progressed = scan_inputs(&mut cursor, states.len(), |index| {
        visits.push(index);
        Ok::<_, Error>(matches!(
            states.get(index),
            Some(actor::InputProgress::DeliveryReady)
        ))
    })?;
    check(progressed && visits == [0, 1, 2, 3] && cursor == 0)
}

#[test]
fn temporary_completion_and_delivery_refusals_preserve_other_candidates() -> Result<(), Error> {
    let states = [
        actor::InputProgress::Finished,
        actor::InputProgress::DeliveryReady,
        actor::InputProgress::Working,
        actor::InputProgress::DeliveryReady,
        actor::InputProgress::DeliveryReady,
    ];
    let mut cursor = 0;
    let mut attempted = Vec::new();
    let progressed = scan_inputs(&mut cursor, states.len(), |index| {
        match states.get(index).ok_or(Error::Stale)? {
            actor::InputProgress::Finished | actor::InputProgress::DeliveryReady => {
                attempted.push(index);
                // The first two original owners are temporarily blocked; the
                // fourth has independent actual room and succeeds.
                Ok(index == 3)
            }
            _ => Ok(false),
        }
    })?;
    check(progressed && attempted == [0, 1, 3] && cursor == 4)?;
    let mut next = None;
    check(scan_inputs(&mut cursor, states.len(), |index| {
        next = Some(index);
        Ok::<_, Error>(true)
    })?)?;
    check(next == Some(4) && cursor == 0)
}

#[test]
fn complete_blocked_input_scan_reports_no_progress_and_keeps_a_finite_cursor() -> Result<(), Error>
{
    let mut cursor = 2;
    let mut visits = Vec::new();
    check(!scan_inputs(&mut cursor, 4, |index| {
        visits.push(index);
        Ok::<_, Error>(false)
    })?)?;
    check(visits == [2, 3, 0, 1] && cursor == 2)?;
    check(!scan_inputs(&mut cursor, 0, |_| {
        Err::<bool, _>(Error::Stale)
    })?)?;
    check(cursor == 2)
}

#[test]
fn every_legal_quantum_finishes_an_idle_class_pass_then_stops_continuations() -> Result<(), Error> {
    for quantum in 1..=64 {
        let mut scan = ClassScan::default();
        let mut visits = Vec::new();
        let mut continuations = 0;
        loop {
            scan.begin_pass();
            for _ in 0..quantum {
                let Some(class) = scan.take_class() else {
                    break;
                };
                visits.push(class);
            }
            if !scan.needs_pass() {
                break;
            }
            continuations += 1;
            check(continuations < 7)?;
        }
        check(visits == [0, 1, 2, 3, 4, 5, 6] && continuations == 6 / quantum)?;
        check(!scan.needs_pass() && scan.take_class().is_none())?;
        // A later real external wake may begin another pass; completion itself
        // never keeps generating a new self-wake.
        scan.begin_pass();
        for class in 0..7 {
            check(scan.take_class() == Some(class))?;
        }
        check(!scan.needs_pass())?;
    }
    Ok(())
}

#[test]
fn one_time_readiness_reaches_an_already_scanned_consumer_at_any_quantum() -> Result<(), Error> {
    for quantum in 1..=64 {
        let mut scan = ClassScan::default();
        let mut hinted = false;
        let mut consumed = false;
        let mut visits = 0;
        let mut continuations = 0;
        loop {
            scan.begin_pass();
            for _ in 0..quantum {
                let Some(class) = scan.take_class() else {
                    break;
                };
                visits += 1;
                // Class2 ran before class4 produced this one actual readiness
                // transition. Retain a pass, but do not report synthetic IO.
                if class == 4 && !hinted {
                    hinted = true;
                    scan.local_work();
                } else if class == 2 && hinted && !consumed {
                    consumed = true;
                    scan.local_work();
                }
            }
            if !scan.needs_pass() {
                break;
            }
            continuations += 1;
            check(continuations < 17)?;
        }
        check(hinted && consumed && visits == 17 && !scan.needs_pass())?;
    }
    Ok(())
}

#[test]
fn repeated_blocked_readiness_does_not_refresh_completed_class_scan() -> Result<(), Error> {
    let mut scan = ClassScan::default();
    let mut cursor = 0;
    let mut attempts = 0;
    scan.begin_pass();
    while let Some(class) = scan.take_class() {
        if class == 6 {
            let actual = scan_inputs(&mut cursor, 3, |_| {
                attempts += 1;
                Ok::<_, Error>(false)
            })?;
            check(!actual)?;
            // Retained terminal/blocked readiness is a query result, so it
            // supplies neither actual progress nor another local-work pass.
        }
    }
    check(attempts == 3 && !scan.needs_pass() && scan.take_class().is_none())
}

#[test]
fn merged_wakes_preserve_child_passes_and_stop_on_stable_terminal_hints() -> Result<(), Error> {
    for quantum in 1..=64 {
        let mut parent = ClassScan::default();
        let mut scheduler = 4usize;
        let mut runtime = 19usize;
        let mut terminal_queries = 0;
        let mut stable_terminal_queries = 0;
        // Initial work, an unchanged terminal-only external wake, then new
        // local work must all obey the same coalesced continuation rule.
        for phase in 0..3 {
            if phase == 2 {
                scheduler = 4;
                runtime = 3;
            }
            let mut polls = 0;
            loop {
                let mut merged_wake = false;
                parent.begin_pass();
                for _ in 0..quantum {
                    let Some(class) = parent.take_class() else {
                        break;
                    };
                    let pending = match class {
                        2 => {
                            scheduler = scheduler.saturating_sub(quantum);
                            scheduler != 0
                        }
                        4 => {
                            if runtime == 0 {
                                stable_terminal_queries += 1;
                            }
                            runtime = runtime.saturating_sub(quantum);
                            // Even after child debt completes, its retained
                            // terminal hints remain queryable, without progress.
                            terminal_queries += 1;
                            runtime != 0
                        }
                        _ => false,
                    };
                    merged_wake |= pending;
                }
                parent.retain_children(scheduler != 0 || runtime != 0);
                merged_wake |= parent.needs_pass();
                polls += 1;
                check(polls < 175)?;
                // The executor delivers at most one wake here, regardless of
                // how many nested callers woke during the previous poll.
                if !merged_wake {
                    break;
                }
            }
            check(scheduler == 0 && runtime == 0 && !parent.needs_pass())?;
        }
        check(terminal_queries > 0 && stable_terminal_queries > 0)?;
    }
    Ok(())
}

#[test]
fn parked_retirement_debt_does_not_spin_parent_and_resumes_after_settlement() -> Result<(), Error> {
    let mut parent = ClassScan::default();
    let mut retained = 3usize;
    let mut retiring = true;
    for _ in 0..2 {
        let mut polls = 0;
        loop {
            parent.begin_pass();
            let class = parent.take_class().ok_or(Error::NotFound)?;
            if class == 4 && !retiring {
                retained = retained.saturating_sub(1);
            }
            // The child accessor reports only runnable scan debt; retained
            // physical retirement alone is not local work or fake Activity.
            parent.retain_children(!retiring && retained != 0);
            polls += 1;
            check(polls < 28)?;
            if !parent.needs_pass() {
                break;
            }
        }
        if retiring {
            check(retained == 3 && !parent.needs_pass())?;
            retiring = false; // One actual original physical settlement.
        } else {
            check(retained == 0 && !parent.needs_pass())?;
        }
    }
    Ok(())
}
