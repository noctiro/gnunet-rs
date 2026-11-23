//! Bounded compiler, with interchangeable caller-owned and heap storage.
mod artifacts;
mod automaton;
mod dfa;
mod parser;
mod proof;
mod records;
mod storage;

pub use artifacts::{ArtifactMemory, ArtifactWorkspace};
pub use automaton::{GraphMemory, GraphWorkspace};
pub use proof::{ProofMemory, ProofWorkspace};
pub use records::{
    AutomatonView, Edge, EdgeIter, Edges, Record, RecordMemory, State, StateIter, States,
};
use records::{Layout, Table};
/// Resource whose caller-selected bound refused a complete construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Limit {
    /// Original non-NUL expression bytes.
    ExpressionBytes,
    /// Parenthesis/fragment work stack.
    ParserStack,
    /// NFA nodes.
    NfaStates,
    /// NFA epsilon/byte transitions.
    NfaTransitions,
    /// Subset DFA nodes.
    DfaStates,
    /// Aggregate subset bitset words.
    SubsetWords,
    /// DFA and compressed transition counts.
    Transitions,
    /// Dense proof matrix cells, per one of two matrices.
    MatrixCells,
    /// Shared finite proof expression DAG nodes.
    ProofNodes,
    /// One serialized proof or language expression.
    ProofBytes,
    /// Sum of serialized per-state proofs and language expression.
    TotalProofBytes,
    /// Sum of retained compressed edge label bytes.
    LabelBytes,
    /// Synthetic entry records.
    InitialRecords,
    /// Total synthetic proof bytes, edge metadata and edge label bytes.
    InitialBytes,
    /// An official state block would exceed its native block-size limit.
    BlockBytes,
    /// Explicit scalar work budget.
    Work,
}
/// Original parse/resource error, without partial automaton publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildError {
    /// Invalid official syntax at this original byte offset.
    Syntax {
        /// Original offset, or length for incomplete syntax.
        offset: usize,
    },
    /// Explicit caller bound exhausted.
    Limit(Limit),
    /// Allocator refused fallible reservation.
    Allocation,
    /// Checked arithmetic overflow.
    Overflow,
    /// Two different artifact descriptions use the same SHA-512 key.
    Conflict,
}
/// Independent finite compiler bounds. These are limits, not claimed exact RSS.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Original expression bytes.
    pub expression_bytes: usize,
    /// Parser and graph traversal stack entries.
    pub stack: usize,
    /// Thompson NFA nodes.
    pub nfa_states: usize,
    /// Thompson epsilon/byte edges.
    pub nfa_transitions: usize,
    /// Subset DFA nodes, before minimization.
    pub dfa_states: usize,
    /// Total subset bitset words before minimization.
    pub subset_words: usize,
    /// Total raw or compressed edges.
    pub transitions: usize,
    /// Maximum one proof matrix's cells.
    pub matrix_cells: usize,
    /// Proof expression DAG nodes.
    pub proof_nodes: usize,
    /// Maximum one proof or language expression bytes.
    pub proof_bytes: usize,
    /// Sum of all retained state proofs and language expression bytes.
    pub total_proof_bytes: usize,
    /// Retained compressed labels.
    pub label_bytes: usize,
    /// Synthetic initial entries.
    pub initial_records: usize,
    /// Synthetic proof and bridge-label bytes.
    pub initial_bytes: usize,
    /// Charged graph/DAG/expansion steps, plus state-block dedup work.
    /// Byte copying/hash work is separately bounded by byte limits.
    pub work: u64,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            expression_bytes: 4096,
            stack: 8192,
            nfa_states: 8192,
            nfa_transitions: 16384,
            dfa_states: 512,
            subset_words: 65536,
            transitions: 32768,
            matrix_cells: 262144,
            proof_nodes: 2_000_000,
            proof_bytes: 60000,
            total_proof_bytes: 4_194_304,
            label_bytes: 4_194_304,
            initial_records: 32768,
            initial_bytes: 4_194_304,
            work: 200_000_000,
        }
    }
}
struct Budget {
    limits: Limits,
    steps: u64,
}
impl Budget {
    fn step(&mut self) -> Result<(), BuildError> {
        self.charge(1)
    }
    fn charge(&mut self, count: u64) -> Result<(), BuildError> {
        self.steps = self.steps.checked_add(count).ok_or(BuildError::Overflow)?;
        if self.steps > self.limits.work {
            return Err(BuildError::Limit(Limit::Work));
        }
        Ok(())
    }
}

/// Temporary compiler storage. An admitted automaton borrows only its separate
/// record memory, which allows this workspace to compile another announcement.
pub struct Compiler<'a> {
    graph: GraphWorkspace<'a>,
    proof: ProofWorkspace<'a>,
    artifacts: ArtifactWorkspace<'a>,
}

impl<'a> Compiler<'a> {
    /// Combine the independent graph, proof and artifact workspaces.
    pub fn new(
        graph: GraphWorkspace<'a>,
        proof: ProofWorkspace<'a>,
        artifacts: ArtifactWorkspace<'a>,
    ) -> Self {
        Self {
            graph,
            proof,
            artifacts,
        }
    }

    /// Compile the official byte grammar into caller-owned storage. A rejected
    /// expression leaves the destination empty and all workspace reusable.
    /// Compression one keeps byte edges; zero follows linear paths up to the
    /// resource bounds; other values cap non-start edges. Start edges cap at 24.
    pub fn compile_into<'out, const RECORDS: usize, const EDGES: usize, const TEXT: usize>(
        &mut self,
        expression: &[u8],
        compression: u16,
        limits: Limits,
        output: &'out mut RecordMemory<RECORDS, EDGES, TEXT>,
    ) -> Result<AutomatonView<'out>, BuildError> {
        let layout = self.compile(expression, compression, limits, &mut output.table())?;
        output.layout = Some(layout);
        output.view().ok_or(BuildError::Conflict)
    }

    fn compile(
        &mut self,
        expression: &[u8],
        compression: u16,
        limits: Limits,
        destination: &mut Table<'_>,
    ) -> Result<Layout, BuildError> {
        let mut budget = Budget { limits, steps: 0 };
        let graph = self.graph.build(expression, &mut budget)?;
        let proofs = proof::create(&graph, &mut self.proof, &mut budget)?;
        artifacts::create(
            &graph,
            &proofs,
            &mut self.artifacts,
            destination,
            compression,
            &mut budget,
        )
    }
}

/// Heap-backed ownership of a completed automaton.
#[cfg(feature = "alloc")]
pub struct Automaton {
    table: Table<'static>,
    layout: Layout,
}

#[cfg(feature = "alloc")]
impl Automaton {
    /// Compile the same bounded byte grammar as [`Compiler::compile_into`].
    pub fn compile(
        expression: &[u8],
        compression: u16,
        limits: Limits,
    ) -> Result<Self, BuildError> {
        let mut compiler = Compiler::new(
            GraphWorkspace::heap(),
            ProofWorkspace::heap(),
            ArtifactWorkspace::heap(),
        );
        let mut table = Table::heap();
        let layout = compiler.compile(expression, compression, limits, &mut table)?;
        Ok(Self { table, layout })
    }

    /// Borrow the shared representation.
    #[must_use]
    pub fn view(&self) -> AutomatonView<'_> {
        self.table.view(self.layout)
    }

    /// All minimized states with their original proofs.
    #[must_use]
    pub fn states(&self) -> States<'_> {
        self.view().states()
    }

    /// Number of retained synthetic entry records.
    #[must_use]
    pub const fn initial_count(&self) -> usize {
        self.layout.records - self.layout.states
    }

    /// A synthetic entry, indexed independently of minimized states.
    #[must_use]
    pub fn initial(&self, index: usize) -> Option<Record<'_>> {
        self.view().initial(index)
    }

    /// Language-equivalent expression.
    #[must_use]
    pub fn language_expression(&self) -> &[u8] {
        self.view().language_expression()
    }

    /// Actual charged compiler work.
    #[must_use]
    pub const fn work_used(&self) -> u64 {
        self.layout.work
    }

    /// Match the full input against the retained graph.
    pub fn is_match(&self, input: &[u8]) -> Result<bool, gnunet_types::Error> {
        self.view().is_match(input)
    }
}
