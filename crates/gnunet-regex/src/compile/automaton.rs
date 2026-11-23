//! Caller-owned or heap-backed construction of the same minimized DFA.

use super::{Budget, BuildError, dfa, parser};

pub(super) use super::dfa::Graph;

/// Fixed storage for REGEX parsing, subset construction and minimization.
///
/// Capacity parameters are independent. `STACK` bounds each parser stack and
/// the epsilon-closure work stack. `SUBSET_WORDS` is the total number of
/// 64-bit membership words across all DFA states; `CANDIDATE_WORDS` is the
/// size of one temporary subset (at most `NFA_STATES.div_ceil(64)`). The
/// compiler reports a resource limit when its policy or storage is exhausted.
pub struct GraphMemory<
    const NFA_STATES: usize,
    const NFA_TRANSITIONS: usize,
    const STACK: usize,
    const DFA_STATES: usize,
    const SUBSET_WORDS: usize,
    const TRANSITIONS: usize,
    const CANDIDATE_WORDS: usize,
> {
    parser: parser::Memory<NFA_STATES, NFA_TRANSITIONS, STACK>,
    dfa: dfa::Memory<DFA_STATES, SUBSET_WORDS, TRANSITIONS, CANDIDATE_WORDS, STACK>,
}

impl<
    const NFA_STATES: usize,
    const NFA_TRANSITIONS: usize,
    const STACK: usize,
    const DFA_STATES: usize,
    const SUBSET_WORDS: usize,
    const TRANSITIONS: usize,
    const CANDIDATE_WORDS: usize,
>
    GraphMemory<
        NFA_STATES,
        NFA_TRANSITIONS,
        STACK,
        DFA_STATES,
        SUBSET_WORDS,
        TRANSITIONS,
        CANDIDATE_WORDS,
    >
{
    /// Initialize a graph workspace; suitable for board-provisioned storage.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            parser: parser::Memory::new(),
            dfa: dfa::Memory::new(),
        }
    }

    /// Borrow the tables needed by one compiler invocation at a time.
    pub fn workspace(&mut self) -> GraphWorkspace<'_> {
        GraphWorkspace {
            parser: self.parser.workspace(),
            dfa: self.dfa.workspace(),
        }
    }
}

impl<
    const NFA_STATES: usize,
    const NFA_TRANSITIONS: usize,
    const STACK: usize,
    const DFA_STATES: usize,
    const SUBSET_WORDS: usize,
    const TRANSITIONS: usize,
    const CANDIDATE_WORDS: usize,
> Default
    for GraphMemory<
        NFA_STATES,
        NFA_TRANSITIONS,
        STACK,
        DFA_STATES,
        SUBSET_WORDS,
        TRANSITIONS,
        CANDIDATE_WORDS,
    >
{
    fn default() -> Self {
        Self::new()
    }
}

/// Exclusive borrow of the tables used by the REGEX graph compiler.
pub struct GraphWorkspace<'storage> {
    parser: parser::Workspace<'storage>,
    dfa: dfa::Workspace<'storage>,
}

impl GraphWorkspace<'_> {
    #[cfg(feature = "alloc")]
    pub(super) fn heap() -> Self {
        Self {
            parser: parser::Workspace::heap(),
            dfa: dfa::Workspace::heap(),
        }
    }

    /// Return a minimized graph whose initial state and partitions are
    /// assigned in the same deterministic order for either storage backend.
    pub(super) fn build(
        &mut self,
        expression: &[u8],
        budget: &mut Budget,
    ) -> Result<Graph<'_>, BuildError> {
        let parsed = parser::parse(expression, &mut self.parser, budget)?;
        let graph = self.dfa.determinize(parsed, budget);
        self.parser.release();
        graph
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile::{Limit, Limits};

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "assertions report graph regressions"
    )]
    fn graph_compacts_equivalent_rows_after_capacity_refusal() -> Result<(), BuildError> {
        let mut memory = GraphMemory::<16, 20, 16, 8, 8, 4, 1>::new();
        let mut workspace = memory.workspace();
        let mut budget = Budget {
            limits: Limits {
                transitions: 3,
                ..Limits::default()
            },
            steps: 0,
        };
        assert!(matches!(
            workspace.build(b"ab|cb", &mut budget),
            Err(BuildError::Limit(Limit::Transitions))
        ));

        let mut budget = Budget {
            limits: Limits::default(),
            steps: 0,
        };
        let graph = workspace.build(b"ab|cb", &mut budget)?;
        assert_eq!(graph.len(), 3);
        let first = graph.row(0);
        assert!(!first.accept);
        assert_eq!(first.edges.len(), 2);
        assert_eq!((first.edges[0].byte, first.edges[0].to), (b'a', 1));
        assert_eq!((first.edges[1].byte, first.edges[1].to), (b'c', 1));
        let middle = graph.row(1);
        assert!(!middle.accept);
        assert_eq!(middle.edges.len(), 1);
        assert_eq!((middle.edges[0].byte, middle.edges[0].to), (b'b', 2));
        let last = graph.row(2);
        assert!(last.accept);
        assert!(last.edges.is_empty());
        Ok(())
    }
}
