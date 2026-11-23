//! Pure original-owner progression; closures perform no native operation.
use super::*;
use std::cell::{Cell, RefCell};

#[test]
fn terminal_originals_are_sampled_before_the_one_close_and_delivered_afterward() -> io::Result<()> {
    let mut admission = Admission::new(17);
    let receive = Arc::new(53);
    let send = Arc::new(995);
    admission.submit(Direction::Receive, &receive, |_| Ok(()))?;
    admission.submit(Direction::Send, &send, |_| Ok(()))?;
    let events = RefCell::new(Vec::new());
    let close = admission.close(
        |handle, original| {
            events.borrow_mut().push((handle, *original));
            Some(if *original == 995 {
                Err(io::Error::from_raw_os_error(995))
            } else {
                Ok(*original)
            })
        },
        |handle| {
            events.borrow_mut().push((handle, 0));
            Err(5)
        },
    );
    if close.err().and_then(|error| error.raw_os_error()) != Some(5)
        || *events.borrow() != [(17, 53), (17, 995), (17, 0)]
        || admission.original().is_ok()
    {
        return Err(io::Error::other(
            "original terminal observations did not precede close",
        ));
    }
    let queries = Cell::new(0);
    let received = admission.complete(Direction::Receive, &receive, |_, _| {
        queries.set(queries.get() + 1);
        Ok(0)
    })??;
    let sent = admission.complete(Direction::Send, &send, |_, _| {
        queries.set(queries.get() + 1);
        Ok(0)
    })?;
    let repeated = admission.close(
        |_, _| {
            queries.set(queries.get() + 1);
            None
        },
        |_| {
            queries.set(queries.get() + 1);
            Ok(())
        },
    );
    if received != 53
        || sent.err().and_then(|error| error.raw_os_error()) != Some(995)
        || repeated.err().and_then(|error| error.raw_os_error()) != Some(5)
        || queries.get() != 0
    {
        return Err(io::Error::other(
            "close changed a terminal result or retried native work",
        ));
    }
    Ok(())
}

#[test]
fn pending_at_close_remains_unknown_without_requerying_a_closed_handle() -> io::Result<()> {
    let mut admission = Admission::new(23);
    let original = Arc::new(7);
    admission.submit(Direction::Receive, &original, |_| Ok(()))?;
    let queries = Cell::new(0);
    let closed = Cell::new(false);
    admission.close(
        |handle, _| {
            queries.set(queries.get() + 1);
            if handle == 23 && !closed.get() {
                None
            } else {
                Some(Ok(1))
            }
        },
        |handle| {
            closed.set(handle == 23);
            Ok(())
        },
    )?;
    let completion = admission.complete(Direction::Receive, &original, |_, _| {
        queries.set(queries.get() + 1);
        Ok(1)
    });
    if !closed.get()
        || queries.get() != 1
        || completion.err().map(|error| error.kind()) != Some(io::ErrorKind::NotConnected)
    {
        return Err(io::Error::other(
            "pending original acquired an invented post-close result",
        ));
    }
    Ok(())
}

#[test]
fn competing_allocation_cannot_remove_an_original_or_its_completion() -> io::Result<()> {
    let mut admission = Admission::new(31);
    let original = Arc::new(53);
    let replacement = Arc::new(53);
    admission.submit(Direction::Send, &original, |_| Ok(()))?;
    let refused = Cell::new(false);
    let second = admission.submit(Direction::Send, &replacement, |_| {
        refused.set(true);
        Ok(())
    });
    let wrong = admission.complete(Direction::Send, &replacement, |_, _| {
        refused.set(true);
        Ok(0)
    });
    let delivered = admission.complete(Direction::Send, &original, |handle, original| {
        if handle == 31 {
            Ok(*original)
        } else {
            Err(io::ErrorKind::NotConnected.into())
        }
    })??;
    admission.close(
        |_, _| {
            refused.set(true);
            None
        },
        |_| Ok(()),
    )?;
    if second.err().map(|error| error.kind()) != Some(io::ErrorKind::WouldBlock)
        || wrong.is_ok()
        || delivered != 53
        || refused.get()
    {
        return Err(io::Error::other(
            "competing owner removed or replaced the original",
        ));
    }
    Ok(())
}

#[test]
fn rejected_submission_leaves_no_loan_for_close_to_query() -> io::Result<()> {
    let mut admission = Admission::new(41);
    let refused = Arc::new(1);
    let result = admission.submit(Direction::Receive, &refused, |_| {
        Err(io::Error::from_raw_os_error(5))
    });
    let original = Arc::new(2);
    admission.submit(Direction::Receive, &original, |_| Ok(()))?;
    let retained = Arc::clone(&original);
    drop(original);
    let observed = Cell::new(0);
    admission.close(
        |_, original| {
            observed.set(*original);
            Some(Ok(*original))
        },
        |_| Ok(()),
    )?;
    let delivered = admission.complete(Direction::Receive, &retained, |_, _| {
        Err(io::ErrorKind::NotConnected.into())
    })??;
    if result.err().and_then(|error| error.raw_os_error()) != Some(5)
        || observed.get() != 2
        || delivered != 2
    {
        return Err(io::Error::other(
            "rejected submission displaced the later original",
        ));
    }
    Ok(())
}
