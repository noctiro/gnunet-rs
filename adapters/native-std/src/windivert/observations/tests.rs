//! Pure capture-time binding fixtures; no Windows provider or SDK call.
use super::*;

#[test]
fn a_reused_index_never_rebinds_an_older_queued_capture() -> io::Result<()> {
    let first = Identity::fixture(7, 1);
    let replacement = Identity::fixture(7, 2);
    let mut history = History::new(100, vec![first.clone()], 1000)?;
    history.refresh(200, vec![replacement.clone()])?;
    if history.get(150, 201, 7)? != &first
        || history.get(201, 201, 7)? != &replacement
        || history.get(200, 201, 7).is_ok()
    {
        return Err(io::Error::other("queued capture adopted a later interface"));
    }
    history.refresh(300, vec![replacement.clone()])?;
    if history.get(150, 301, 7)? != &first {
        return Err(io::Error::other(
            "unchanged scan discarded the original view",
        ));
    }
    history.refresh(400, vec![Identity::fixture(7, 3)])?;
    if history.get(150, 401, 7).is_ok() || history.get(250, 401, 7)? != &replacement {
        return Err(io::Error::other(
            "bounded observation history rebound an old capture",
        ));
    }
    Ok(())
}

#[test]
fn new_interfaces_and_failed_refreshes_cannot_rewrite_an_older_view() -> io::Result<()> {
    let first = Identity::fixture(7, 1);
    let second = Identity::fixture(8, 2);
    let mut history = History::new(100, vec![first.clone()], 1000)?;
    history.refresh(200, vec![second.clone(), first.clone()])?;
    if history.get(150, 201, 8).is_ok() || history.get(201, 201, 8)? != &second {
        return Err(io::Error::other(
            "new interface was backdated into a queued capture",
        ));
    }
    if history
        .refresh(300, vec![second.clone(), second.clone()])
        .is_ok()
        || history.refresh(199, vec![]).is_ok()
        || history.refresh(200, vec![]).is_ok()
        || history.get(250, 250, 7)? != &first
        || history.get(250, 250, 8)? != &second
        || history.get(99, 250, 7).is_ok()
    {
        return Err(io::Error::other(
            "failed observation changed capture binding",
        ));
    }
    Ok(())
}

#[test]
fn unchanged_refreshes_preserve_capture_history_but_advance_freshness() -> io::Result<()> {
    let first = Identity::fixture(7, 1);
    let mut history = History::new(100, vec![first.clone()], 100)?;
    if history.get(150, 199, 7)? != &first || history.get(150, 200, 7).is_ok() {
        return Err(io::Error::other("expired capture observation was admitted"));
    }
    history.refresh(300, vec![first.clone()])?;
    if history.get(150, 399, 7)? != &first
        || history.get(150, 400, 7).is_ok()
        || history.get(401, 399, 7).is_ok()
        || history.get(150, 299, 7).is_ok()
        || history.refresh(250, vec![first.clone()]).is_ok()
        || history.refresh(250, vec![Identity::fixture(7, 2)]).is_ok()
        || history.refresh(300, vec![Identity::fixture(7, 2)]).is_ok()
        || history.get(150, 301, 7)? != &first
    {
        return Err(io::Error::other(
            "unchanged scan lost its clock or history fence",
        ));
    }
    // A rejected refresh cannot extend the latest successful observation.
    if history.refresh(350, vec![first.clone(), first]).is_ok()
        || history.get(301, 400, 7).is_ok()
        || History::new(100, Vec::new(), 0).is_ok()
    {
        return Err(io::Error::other(
            "invalid refresh extended observation authority",
        ));
    }
    Ok(())
}
