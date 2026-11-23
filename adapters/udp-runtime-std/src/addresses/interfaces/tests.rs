//! Refused prepared claims preserve independent local publication facts.
use super::*;

#[test]
fn refused_snapshot_preserves_claims_feed_membership_and_original_write_facts()
-> Result<(), crate::Cause> {
    let original = "192.0.2.1:2086".parse()?;
    let replacement = "192.0.2.2:2086".parse()?;
    let mut owner = Addresses::new(
        4,
        1024,
        Duration::from_secs(30),
        HelloPublisher::Communicator,
    )?;
    owner.replace_interfaces(&[original], &mut |_| Ok(2))?;
    owner.row(original, 2)?;
    // Fixture of a previously whole-written ADD and its included HELLO row;
    // no native publication or FEED is performed by this unit test.
    owner.rows[0].submitted = true;
    owner.rows[0].live = true;
    owner.rows[0].included = true;
    owner.direct_feed.as_mut().ok_or(Fault::NotReady)?.version = 7;
    owner.report.clear_feed_written = true;
    drop(owner.prepare_interfaces(&[replacement], &mut |_| Ok(3))?);
    let refused = match owner.prepare_interfaces(&[replacement, original], &mut |address| {
        if address == original {
            Err(io::Error::other("fixture classifier failed"))
        } else {
            Ok(3)
        }
    }) {
        Err(Failure::Network(error)) => error.to_string() == "fixture classifier failed",
        _ => false,
    };
    if !refused {
        return Err("expected original classification refusal".into());
    }
    if owner.claims.len() != 1
        || owner.claims[0].address != original
        || owner.direct_feed.as_ref().map(|feed| feed.version) != Some(7)
        || !owner.rows[0].included
        || !owner.rows[0].live
        || !owner.report.clear_feed_written
    {
        return Err("refused projection changed live claims or write facts".into());
    }
    owner.direct_feed.as_mut().ok_or(Fault::NotReady)?.version = u64::MAX;
    if !matches!(
        owner.prepare_interfaces(&[], &mut |_| Ok(3)),
        Err(Failure::Core(Fault::Overflow))
    ) || owner.claims[0].address != original
        || !owner.rows[0].included
    {
        return Err("version preflight changed claims before refusing overflow".into());
    }
    owner.direct_feed.as_mut().ok_or(Fault::NotReady)?.version = 7;
    owner
        .prepare_interfaces(&[replacement], &mut |_| Ok(3))?
        .commit();
    if owner.claims.len() != 1
        || owner.claims[0].address != replacement
        || owner.direct_feed.as_ref().map(|feed| feed.version) != Some(8)
        || owner.rows[0].included
        || !owner.rows[0].live
        || !owner.rows[0].submitted
        || owner.report.clear_feed_written
        || owner.report.remove_written != 0
        || owner.report.feed_written != 0
    {
        return Err("commit lost original ADD facts or invented withdrawal/FEED completion".into());
    }
    Ok(())
}

#[test]
fn transport_owned_hello_still_requires_communicator_withdrawal() -> Result<(), crate::Cause> {
    let original = "192.0.2.1:2086".parse()?;
    let mut owner = Addresses::new(4, 1024, Duration::from_secs(30), HelloPublisher::Transport)?;
    owner.replace_interfaces(&[original], &mut |_| Ok(2))?;
    owner.row(original, 2)?;
    // Model an original whole ADD. Stopping leaves the row live until DEL is written.
    owner.rows[0].submitted = true;
    owner.rows[0].live = true;
    owner.reconcile_feed()?;
    owner.begin_close();
    let report = owner.report();
    if owner.direct_feed.is_some()
        || report.pending_feed
        || report.desired_feed_unsubmitted
        || owner.idle()
    {
        return Err("delegation discarded an original withdrawal or created a PILS FEED".into());
    }
    Ok(())
}
