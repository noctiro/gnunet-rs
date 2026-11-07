//! Historical local graph facts, separate from current graph confirmation.
use super::{
    codec::{Reader, Writer},
    model::{Attempt, ModelError},
    plan::{Artifact, Plan},
};
use crate::namespace::graph::Binding;

/// Original exact update-graph target for one tracked namespace publication.
/// None in the manifest means no graph bookkeeping, including for an empty
/// wire update. A present target retains an explicitly selected empty update.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GraphTarget {
    /// Original graph WAL identity and public namespace, not a pathname alias.
    pub binding: Binding,
}
impl GraphTarget {
    pub(super) fn validate(self, plan: &Plan) -> Result<(), ModelError> {
        match &plan.artifact {
            Artifact::Namespace { public, .. }
                if public == &self.binding.namespace && plan.puts.len() == 1 =>
            {
                Ok(())
            }
            _ => Err(ModelError::Binding),
        }
    }
}
/// An original confirmed graph effect. Only an actual private Graph TaskReceipt
/// authorizes its runtime creation; decoding these fields alone cannot establish
/// that the graph still has the record or that current payloads authenticate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Recorded {
    /// Original physical graph WAL identity and namespace.
    pub binding: Binding,
    /// Original publication task identity used as the stable graph origin.
    pub origin: [u8; 32],
    /// Original actual accepted single namespace PUT and its intent generation.
    pub attempt: Attempt,
    /// Exact original zero-based graph publication record position.
    pub record_index: usize,
    /// Hash of the exact original graph record body, including task origin.
    pub body_hash: [u8; 64],
}
/// Constant-space graph history. A missing fact after native acceptance requires
/// graph-only reconciliation; it never authorizes another weighted PUT.
#[derive(Default)]
pub struct State {
    /// Original confirmed graph effect, retained separately from live checks.
    pub recorded: Option<Recorded>,
}
impl State {
    pub(super) fn complete(&self, target: Option<GraphTarget>) -> bool {
        target.is_none() || self.recorded.is_some()
    }
    pub(super) fn check(
        &self,
        fact: &Recorded,
        target: Option<GraphTarget>,
        task_id: [u8; 32],
        accepted: Option<Attempt>,
    ) -> Result<(), ModelError> {
        let target = target.ok_or(ModelError::Binding)?;
        if fact.binding != target.binding
            || fact.origin != task_id
            || accepted != Some(fact.attempt)
        {
            return Err(ModelError::Binding);
        }
        // The runtime confirms an identical already admitted fact without a
        // second Task WAL append. A conflicting historical effect cannot replace it.
        if self.recorded.is_some() {
            return Err(ModelError::Transition);
        }
        Ok(())
    }
}
pub(super) fn put_target(w: &mut Writer, target: Option<GraphTarget>) -> Result<(), ModelError> {
    w.u8(u8::from(target.is_some()))?;
    if let Some(target) = target {
        put_binding(w, target.binding)?;
    }
    Ok(())
}
pub(super) fn get_target(r: &mut Reader<'_>) -> Result<Option<GraphTarget>, ModelError> {
    match r.u8()? {
        0 => Ok(None),
        1 => Ok(Some(GraphTarget {
            binding: get_binding(r)?,
        })),
        _ => Err(ModelError::Format),
    }
}
fn put_binding(w: &mut Writer, binding: Binding) -> Result<(), ModelError> {
    w.raw(&binding.store_id)?;
    w.raw(&binding.namespace)
}
fn get_binding(r: &mut Reader<'_>) -> Result<Binding, ModelError> {
    Ok(Binding {
        store_id: r.array()?,
        namespace: r.array()?,
    })
}
pub(super) fn put_recorded(w: &mut Writer, fact: Recorded) -> Result<(), ModelError> {
    put_binding(w, fact.binding)?;
    w.raw(&fact.origin)?;
    super::codec::put_attempt(w, fact.attempt)?;
    w.usize(fact.record_index)?;
    w.raw(&fact.body_hash)
}
pub(super) fn get_recorded(r: &mut Reader<'_>) -> Result<Recorded, ModelError> {
    Ok(Recorded {
        binding: get_binding(r)?,
        origin: r.array()?,
        attempt: super::codec::get_attempt(r)?,
        record_index: r.usize()?,
        body_hash: r.array()?,
    })
}

#[cfg(test)]
mod tests;
