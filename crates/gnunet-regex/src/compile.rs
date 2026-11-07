//! Complete explicit-alloc compiler with bounded fallible admission.
use crate::{BlockEdge, EdgeSource, Hash, encode_state, proof_key, state_block_len};
use alloc::vec::Vec;
mod artifacts;
mod dfa;
mod parser;
mod proof;
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
fn push<T>(vec: &mut Vec<T>, value: T, max: usize, kind: Limit) -> Result<(), BuildError> {
    if vec.len() >= max {
        return Err(BuildError::Limit(kind));
    }
    vec.try_reserve(1).map_err(|_| BuildError::Allocation)?;
    vec.push(value);
    Ok(())
}
fn filled<T: Clone>(count: usize, value: T) -> Result<Vec<T>, BuildError> {
    let mut vec = Vec::new();
    vec.try_reserve_exact(count)
        .map_err(|_| BuildError::Allocation)?;
    vec.resize(count, value);
    Ok(vec)
}
fn bytes(input: &[u8]) -> Result<Vec<u8>, BuildError> {
    let mut vec = Vec::new();
    vec.try_reserve_exact(input.len())
        .map_err(|_| BuildError::Allocation)?;
    vec.extend_from_slice(input);
    Ok(vec)
}
/// Owned exact transition bytes and destination state proof key.
#[derive(Debug)]
pub struct Edge {
    label: Vec<u8>,
    destination: Hash,
    target: usize,
}
impl Edge {
    /// Nonempty exact label, with no regex interpretation during traversal.
    #[must_use]
    pub fn label(&self) -> &[u8] {
        &self.label
    }
    /// Exact SHA-512 of the destination state's original proof bytes.
    #[must_use]
    pub const fn destination(&self) -> Hash {
        self.destination
    }
}
impl EdgeSource for [Edge] {
    fn len(&self) -> usize {
        <[Edge]>::len(self)
    }
    fn edge(&self, index: usize) -> Option<BlockEdge<'_>> {
        self.get(index).map(|e| BlockEdge {
            destination: e.destination,
            label: &e.label,
        })
    }
}
/// One minimized state with its complete proof and compressed transitions.
#[derive(Debug)]
pub struct State {
    proof: Vec<u8>,
    key: Hash,
    accepting: bool,
    edges: Vec<Edge>,
}
impl State {
    /// Borrow exact pure state artifact.
    #[must_use]
    pub fn record(&self) -> Record<'_> {
        Record {
            proof: &self.proof,
            key: self.key,
            accepting: self.accepting,
            edges: &self.edges,
        }
    }
}
/// One self-contained pure state block view, not a submitted announcement.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    /// Exact unhashed proof bytes, without NUL.
    pub proof: &'a [u8],
    /// SHA-512 of exactly proof.
    pub key: Hash,
    /// Whether consuming the full string at this state accepts.
    pub accepting: bool,
    /// Nonempty literal edge labels and exact destination proof keys.
    pub edges: &'a [Edge],
}
impl Record<'_> {
    /// Checked official block byte size.
    pub fn encoded_len(self) -> Result<usize, gnunet_types::Error> {
        state_block_len(self.proof, self.edges)
    }
    /// Encode official state block into caller storage, without any network effect.
    pub fn encode(self, out: &mut [u8]) -> Result<usize, gnunet_types::Error> {
        encode_state(self.proof, self.accepting, self.edges, out)
    }
}
struct Initial {
    proof: Vec<u8>,
    accepting: bool,
    edges: Vec<Edge>,
}
/// Complete independent automaton. Each construction is atomic and fallible;
/// default-noalloc hashing/encoding does not imply the compiler allocates nothing.
pub struct Automaton {
    states: Vec<State>,
    initial: Vec<Initial>,
    language: Vec<u8>,
    work: u64,
}
impl Automaton {
    /// Compile the complete official byte grammar: grouping/union, implicit
    /// concatenation, and postfix */+/?; every other non-NUL byte is literal.
    /// `compression=1` means byte edges, 0 unbounded linear paths (still resource
    /// bounded), otherwise an upper bound per non-start edge. Start edges cap24.
    pub fn compile(
        expression: &[u8],
        compression: u16,
        limits: Limits,
    ) -> Result<Self, BuildError> {
        let mut budget = Budget { limits, steps: 0 };
        let nfa = parser::parse(expression, &mut budget)?;
        let dfa = dfa::determinize(nfa, &mut budget)?;
        let dfa = dfa::minimize(dfa, &mut budget)?;
        let (proofs, language) = proof::create(&dfa, &mut budget)?;
        let states = artifacts::compress(&dfa, proofs, compression, &mut budget)?;
        let initial = artifacts::initial(&states, &mut budget)?;
        let result = Self {
            states,
            initial,
            language,
            work: budget.steps,
        };
        for state in &result.states {
            let count = state
                .edges
                .len()
                .checked_mul(
                    state
                        .edges
                        .len()
                        .checked_add(1)
                        .ok_or(BuildError::Overflow)?,
                )
                .and_then(|n| n.checked_div(2))
                .ok_or(BuildError::Overflow)?;
            budget.charge(u64::try_from(count).map_err(|_| BuildError::Overflow)?)?;
            state
                .record()
                .encoded_len()
                .map_err(|_| BuildError::Limit(Limit::BlockBytes))?;
        }
        for i in 0..result.initial.len() {
            let edge_count = result.initial[i].edges.len();
            let count = edge_count
                .checked_mul(edge_count.checked_add(1).ok_or(BuildError::Overflow)?)
                .and_then(|n| n.checked_div(2))
                .ok_or(BuildError::Overflow)?;
            budget.charge(u64::try_from(count).map_err(|_| BuildError::Overflow)?)?;
            result
                .initial(i)
                .ok_or(BuildError::Conflict)?
                .encoded_len()
                .map_err(|_| BuildError::Limit(Limit::BlockBytes))?;
        }
        Ok(Self {
            work: budget.steps,
            ..result
        })
    }
    /// Full-string byte matching; embedded NUL input is rejected explicitly.
    pub fn is_match(&self, input: &[u8]) -> Result<bool, gnunet_types::Error> {
        if input.contains(&0) {
            return Err(gnunet_types::Error::InvalidInput);
        }
        let mut state = 0;
        let mut at = 0;
        while at < input.len() {
            let row = &self.states[state];
            let found = row
                .edges
                .iter()
                .filter(|e| input[at..].starts_with(&e.label))
                .max_by_key(|e| e.label.len());
            let Some(edge) = found else {
                return Ok(false);
            };
            at += edge.label.len();
            state = edge.target;
        }
        Ok(self.states[state].accepting)
    }
    /// All minimized states, retaining proofs assigned before compression.
    #[must_use]
    pub fn states(&self) -> &[State] {
        &self.states
    }
    /// A language-equivalent expression, not byte-identical C canonicalization.
    #[must_use]
    pub fn language_expression(&self) -> &[u8] {
        &self.language
    }
    /// Complete retained synthetic entry count.
    #[must_use]
    pub fn initial_count(&self) -> usize {
        self.initial.len()
    }
    /// Borrow exact entry record. Entries are indexed independently of states.
    #[must_use]
    pub fn initial(&self, index: usize) -> Option<Record<'_>> {
        self.initial.get(index).map(|i| Record {
            proof: &i.proof,
            key: proof_key(&i.proof),
            accepting: i.accepting,
            edges: &i.edges,
        })
    }
    /// Actual shared scalar algorithmic work charged by this construction.
    #[must_use]
    pub const fn work_used(&self) -> u64 {
        self.work
    }
}
