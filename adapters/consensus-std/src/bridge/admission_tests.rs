//! Original public core admission/retirement and typed shared-clock boundaries.
//! No PILS identity, native write receipt, remote DONE or credit is fabricated.
use super::*;
use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, SystemClock};
type Failure = Box<dyn std::error::Error>;

struct Clock {
    now: u64,
    refusal: Option<Fault>,
}
impl RuntimeClock for Clock {
    fn sample(&self) -> Result<ClockSample, Fault> {
        if let Some(error) = self.refusal {
            Err(error)
        } else {
            Ok(ClockSample {
                now: gnunet_types::AbsoluteTime::from_micros(self.now),
                revision: 0,
            })
        }
    }
    fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Fault> {
        SystemClock.subscribe()
    }
}
fn check(value: bool) -> Result<(), Failure> {
    if value {
        Ok(())
    } else {
        Err("original admission ownership boundary changed".into())
    }
}

#[test]
fn never_created_population_keeps_original_unsent_and_local_close_debt() -> Result<(), Failure> {
    for admitted in [false, true] {
        let now = 10_000;
        let domain = core::Instance::new();
        let mut session = core::Session::new(
            &domain,
            [1; 32],
            Join {
                session: [7; 64],
                start: now,
                deadline: 1_000_000,
                peers: &[[1; 32], [2; 32], [3; 32], [4; 32]],
            },
            core::Limits::default(),
            set::Abi::native(),
            now,
        )?;
        // This is a pure public transcript's explicit local effect disposition,
        // not a claim that a native listener exists or a peer wrote anything.
        let listen = session.effect().ok_or("missing listener effect")?.id;
        session.admit_effect(listen)?;
        let _listener = session.complete_effect(listen, Completion::Written)?;
        session.conclude(now)?;
        session.step(now, 64)?;
        let pending = session.effect().ok_or("missing PrepareSet")?;
        let Action::PrepareSet { set: source } = pending.action else {
            return Err("wrong original effect".into());
        };
        let effect = pending.id;
        let end = pending.deadline().ok_or("missing original phase target")?;
        let row = Source {
            id: source,
            native: None,
            cursor: 0,
            mutation: None,
            total: session.set_len(source)?,
            initialized: false,
            retired: None,
        };
        let outer = Bounds {
            expires: 1_000_000,
            hard: Instant::now()
                .checked_add(Duration::from_secs(30))
                .ok_or(Fault::Overflow)?,
        };
        // The provider observes that same original phase boundary only after
        // the pure effect was selected. It cannot renew or globalize this miss.
        let error = Bridge::clamp(
            &Clock {
                now: end,
                refusal: None,
            },
            outer,
            end,
        )
        .err()
        .ok_or("expired original phase was admitted")?;
        check(matches!(error, Error::Protocol(Fault::Deadline)) && !global_error(&error))?;
        if admitted {
            session.admit_effect(effect)?;
        }
        let terminal = retire_uncreated_population(&mut session, &row, effect, error.classified())?;
        check(
            terminal.effect.id == effect
                && terminal.effect.deadline() == Some(end)
                && terminal.completion == Completion::Unsent(Fault::Deadline),
        )?;
        check(
            !session.set_live(source)
                && session.set_context(source)?.retired == Some(Fault::Deadline)
                && session.outcome().failure.is_none()
                && !session.outcome().client_done_written,
        )?;
        // The retained empty ledger cannot become a replacement native source.
        check(
            row.native.is_none()
                && row.retired.is_none()
                && uncreated_population(&session, &row, effect).is_err(),
        )?;
        session.step(now, 64)?;
        check(session.outcome().failure.is_none())?;
    }
    Ok(())
}

#[test]
fn the_same_numeric_clock_refusal_keeps_its_shared_origin() -> Result<(), Failure> {
    let original = Bounds {
        expires: 1_000_000,
        hard: Instant::now()
            .checked_add(Duration::from_secs(30))
            .ok_or(Fault::Overflow)?,
    };
    for fault in [Fault::Deadline, Fault::Capacity] {
        let error = Bridge::clamp(
            &Clock {
                now: 1,
                refusal: Some(fault),
            },
            original,
            500_000,
        )
        .err()
        .ok_or("failed shared clock was admitted")?;
        check(global_error(&error))?;
        let domain = core::Instance::new();
        let mut session = core::Session::new(
            &domain,
            [1; 32],
            Join {
                session: [7; 64],
                start: 10_000,
                deadline: original.expires,
                peers: &[[1; 32], [2; 32]],
            },
            core::Limits::default(),
            set::Abi::native(),
            10_000,
        )?;
        let listen = session.effect().ok_or("missing listener effect")?.id;
        session.admit_effect(listen)?;
        let _listener = session.complete_effect(listen, Completion::Written)?;
        session.conclude(10_000)?;
        session.step(10_000, 64)?;
        let pending = session.effect().ok_or("missing original population")?;
        let Action::PrepareSet { set: source } = pending.action else {
            return Err("wrong original population effect".into());
        };
        let effect = pending.id;
        let mut rows = vec![Source {
            id: source,
            native: None,
            cursor: 0,
            mutation: None,
            total: session.set_len(source)?,
            initialized: false,
            retired: None,
        }];
        session.admit_effect(effect)?;
        remove_uncreated_population(&session, &mut rows, source, effect)?;
        let terminal = session.complete_effect(effect, Completion::Unsent(error.classified()))?;
        check(
            rows.is_empty()
                && terminal.effect.id == effect
                && session.outcome().failure.is_some()
                && !session.set_live(source),
        )?;
        check(matches!(error, Error::Set(set::Error::Clock(
            gnunet_client_host::ConnectError::Protocol(actual))) if actual == fault))?;
        check(!global_error(&Error::Protocol(fault)))?;
    }
    Ok(())
}
