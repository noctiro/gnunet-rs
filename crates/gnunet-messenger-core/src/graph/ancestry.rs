//! Positive ancestry proofs rooted in signed parent links.

use crate::{
    Error, Hash,
    graph::HistoryWorkspace,
    room_history::{HistoryEntry, HistoryRead},
};

/// Prove that one of the signed parents reaches an authenticated anchor.
/// Only complete outer graph records supply intermediate edges. The anchor
/// may have missing parents of its own, and unrelated body semantics grant
/// no authority over a signed edge.
pub(crate) fn has_signed_ancestor(
    mut history: impl HistoryRead,
    parents: &[Hash],
    ancestor: &Hash,
    workspace: &mut HistoryWorkspace<'_>,
) -> Result<bool, Error> {
    if *ancestor == [0; 64] {
        return Ok(false);
    }

    let mut parents = parents.iter().filter(|parent| **parent != [0; 64]);
    let root = loop {
        let Some(parent) = parents.next() else {
            return Ok(false);
        };
        if let Some(root) = history.locate(parent)? {
            break root;
        }
    };
    let mut walk = workspace.start_history(history, root)?;
    for parent in parents {
        if let Some(id) = walk.locate(parent)? {
            walk.schedule(id)?;
        }
    }

    while let Some((_, entry)) = walk.pop()? {
        let HistoryEntry::Accepted(facts) = entry else {
            continue;
        };
        if facts.hash == *ancestor {
            return Ok(true);
        }
        if !facts.complete {
            continue;
        }
        for parent in facts.parents.iter().filter(|parent| **parent != [0; 64]) {
            if let Some(id) = walk.locate(parent)? {
                walk.schedule(id)?;
            }
        }
    }
    Ok(false)
}
