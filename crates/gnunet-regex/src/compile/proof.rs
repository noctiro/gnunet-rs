//! Bounded shared expression DAG for complete start-to-state languages.
//! Kleene matrix recurrence is the same language construction as the official
//! state proof algorithm; spelling is deliberately independent of C simplifier.
use super::automaton::Graph;
use super::storage::Buffer;
use super::{Budget, BuildError, Limit};
const EMPTY: usize = 0;
const EPSILON: usize = 1;
#[derive(Clone, Copy)]
enum Kind {
    Empty,
    Epsilon,
    Byte(u8),
    Union(usize, usize),
    Concat(usize, usize),
    Star(usize),
    Optional(usize),
}
#[derive(Clone, Copy)]
struct Expr {
    kind: Kind,
    len: usize,
}
struct Arena<'a, 'slots> {
    nodes: &'a mut Buffer<'slots, Expr>,
}
#[derive(Clone, Copy)]
enum Task {
    Node(usize),
    Byte(u8),
}

#[derive(Clone, Copy)]
struct Span {
    start: usize,
    end: usize,
}

impl Span {
    const EMPTY: Self = Self { start: 0, end: 0 };

    fn bytes(self, text: &[u8]) -> &[u8] {
        &text[self.start..self.end]
    }
}

impl Arena<'_, '_> {
    fn add(&mut self, kind: Kind, len: Option<usize>, b: &mut Budget) -> Result<usize, BuildError> {
        b.step()?;
        let len = len.ok_or(BuildError::Overflow)?;
        if len > b.limits.proof_bytes {
            return Err(BuildError::Limit(Limit::ProofBytes));
        }
        let id = self.nodes.len();
        self.nodes
            .push(Expr { kind, len }, b.limits.proof_nodes, Limit::ProofNodes)?;
        Ok(id)
    }
    fn union(&mut self, a: usize, c: usize, b: &mut Budget) -> Result<usize, BuildError> {
        if a == EMPTY || a == c {
            return Ok(c);
        }
        if c == EMPTY {
            return Ok(a);
        }
        if a == EPSILON || c == EPSILON {
            let target = if a == EPSILON { c } else { a };
            if matches!(self.nodes[target].kind, Kind::Star(_) | Kind::Optional(_)) {
                return Ok(target);
            }
            return self.add(
                Kind::Optional(target),
                self.nodes[target].len.checked_add(3),
                b,
            );
        }
        self.add(
            Kind::Union(a, c),
            self.nodes[a]
                .len
                .checked_add(self.nodes[c].len)
                .and_then(|n| n.checked_add(3)),
            b,
        )
    }
    fn concat(&mut self, a: usize, c: usize, b: &mut Budget) -> Result<usize, BuildError> {
        if a == EMPTY || c == EMPTY {
            return Ok(EMPTY);
        }
        if a == EPSILON {
            return Ok(c);
        }
        if c == EPSILON {
            return Ok(a);
        }
        self.add(
            Kind::Concat(a, c),
            self.nodes[a].len.checked_add(self.nodes[c].len),
            b,
        )
    }
    fn star(&mut self, a: usize, b: &mut Budget) -> Result<usize, BuildError> {
        if a == EMPTY || a == EPSILON {
            return Ok(EPSILON);
        }
        if matches!(self.nodes[a].kind, Kind::Star(_)) {
            return Ok(a);
        }
        let target = match self.nodes[a].kind {
            Kind::Optional(inner) => inner,
            _ => a,
        };
        self.add(Kind::Star(target), self.nodes[target].len.checked_add(3), b)
    }
    fn render(
        &self,
        id: usize,
        stack: &mut Buffer<'_, Task>,
        output: &mut Buffer<'_, u8>,
        b: &mut Budget,
    ) -> Result<Span, BuildError> {
        let start = output.len();
        let end = start
            .checked_add(self.nodes[id].len)
            .ok_or(BuildError::Overflow)?;
        output.resize(end, 0, b.limits.total_proof_bytes, Limit::TotalProofBytes)?;
        let output = &mut output[start..end];
        let mut written = 0;
        stack.clear();
        stack.push(Task::Node(id), b.limits.stack, Limit::ParserStack)?;
        while let Some(task) = stack.pop() {
            b.step()?;
            let byte = match task {
                Task::Byte(byte) => byte,
                Task::Node(node) => match self.nodes[node].kind {
                    Kind::Empty | Kind::Epsilon => continue,
                    Kind::Byte(byte) => byte,
                    Kind::Concat(a, c) => {
                        stack.push(Task::Node(c), b.limits.stack, Limit::ParserStack)?;
                        stack.push(Task::Node(a), b.limits.stack, Limit::ParserStack)?;
                        continue;
                    }
                    Kind::Union(a, c) => {
                        for task in [
                            Task::Byte(b')'),
                            Task::Node(c),
                            Task::Byte(b'|'),
                            Task::Node(a),
                            Task::Byte(b'('),
                        ] {
                            stack.push(task, b.limits.stack, Limit::ParserStack)?;
                        }
                        continue;
                    }
                    Kind::Star(a) | Kind::Optional(a) => {
                        let op = if matches!(self.nodes[node].kind, Kind::Star(_)) {
                            b'*'
                        } else {
                            b'?'
                        };
                        for task in [
                            Task::Byte(op),
                            Task::Byte(b')'),
                            Task::Node(a),
                            Task::Byte(b'('),
                        ] {
                            stack.push(task, b.limits.stack, Limit::ParserStack)?;
                        }
                        continue;
                    }
                },
            };
            *output.get_mut(written).ok_or(BuildError::Overflow)? = byte;
            written += 1;
        }
        if written != output.len() {
            return Err(BuildError::Overflow);
        }
        Ok(Span { start, end })
    }
}

/// Caller-owned K-path proof workspace. Cells are the capacity of each matrix;
/// text holds the combined state proofs and the language expression.
pub struct ProofMemory<
    const CELLS: usize,
    const NODES: usize,
    const STACK: usize,
    const STATES: usize,
    const TEXT: usize,
> {
    first: [usize; CELLS],
    second: [usize; CELLS],
    nodes: [Expr; NODES],
    stack: [Task; STACK],
    states: [Span; STATES],
    text: [u8; TEXT],
}

impl<
    const CELLS: usize,
    const NODES: usize,
    const STACK: usize,
    const STATES: usize,
    const TEXT: usize,
> ProofMemory<CELLS, NODES, STACK, STATES, TEXT>
{
    /// Empty storage, suitable for constant initialization.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            first: [EMPTY; CELLS],
            second: [EMPTY; CELLS],
            nodes: [Expr {
                kind: Kind::Empty,
                len: 0,
            }; NODES],
            stack: [Task::Node(EMPTY); STACK],
            states: [Span::EMPTY; STATES],
            text: [0; TEXT],
        }
    }

    /// Borrow this storage exclusively for proof generation.
    pub fn workspace(&mut self) -> ProofWorkspace<'_> {
        ProofWorkspace {
            first: Buffer::fixed(&mut self.first),
            second: Buffer::fixed(&mut self.second),
            nodes: Buffer::fixed(&mut self.nodes),
            stack: Buffer::fixed(&mut self.stack),
            states: Buffer::fixed(&mut self.states),
            text: Buffer::fixed(&mut self.text),
        }
    }
}

impl<
    const CELLS: usize,
    const NODES: usize,
    const STACK: usize,
    const STATES: usize,
    const TEXT: usize,
> Default for ProofMemory<CELLS, NODES, STACK, STATES, TEXT>
{
    fn default() -> Self {
        Self::new()
    }
}

/// Exclusive workspace borrowed from [`ProofMemory`].
pub struct ProofWorkspace<'a> {
    first: Buffer<'a, usize>,
    second: Buffer<'a, usize>,
    nodes: Buffer<'a, Expr>,
    stack: Buffer<'a, Task>,
    states: Buffer<'a, Span>,
    text: Buffer<'a, u8>,
}

#[cfg(feature = "alloc")]
impl ProofWorkspace<'static> {
    pub(super) fn heap() -> Self {
        Self {
            first: Buffer::heap(),
            second: Buffer::heap(),
            nodes: Buffer::heap(),
            stack: Buffer::heap(),
            states: Buffer::heap(),
            text: Buffer::heap(),
        }
    }
}

pub(super) struct Proofs<'a> {
    states: &'a [Span],
    text: &'a [u8],
    language: Span,
}

impl<'a> Proofs<'a> {
    pub(super) fn states(&self) -> impl ExactSizeIterator<Item = &'a [u8]> {
        self.states.iter().map(|span| span.bytes(self.text))
    }

    pub(super) fn language(&self) -> &'a [u8] {
        self.language.bytes(self.text)
    }
}

pub(super) fn create<'work>(
    dfa: &Graph<'_>,
    workspace: &'work mut ProofWorkspace<'_>,
    b: &mut Budget,
) -> Result<Proofs<'work>, BuildError> {
    let ProofWorkspace {
        first,
        second,
        nodes,
        stack,
        states,
        text,
    } = workspace;
    let n = dfa.len();
    let cells = n.checked_mul(n).ok_or(BuildError::Overflow)?;
    first.clear();
    second.clear();
    nodes.clear();
    states.clear();
    text.clear();
    first.resize(cells, EMPTY, b.limits.matrix_cells, Limit::MatrixCells)?;
    second.resize(cells, EMPTY, b.limits.matrix_cells, Limit::MatrixCells)?;
    let mut arena = Arena { nodes };
    arena.add(Kind::Empty, Some(0), b)?;
    arena.add(Kind::Epsilon, Some(0), b)?;
    let mut literals = [EMPTY; 256];
    let mut last = &mut first[..];
    let mut next = &mut second[..];
    for (i, row) in dfa.rows().enumerate() {
        for edge in row.edges {
            b.step()?;
            let byte = usize::from(edge.byte);
            if literals[byte] == EMPTY {
                literals[byte] = arena.add(Kind::Byte(edge.byte), Some(1), b)?;
            }
            let at = i * n + edge.to;
            last[at] = arena.union(last[at], literals[byte], b)?;
        }
        last[i * n + i] = arena.union(last[i * n + i], EPSILON, b)?;
    }
    for k in 0..n {
        let looped = arena.star(last[k * n + k], b)?;
        for i in 0..n {
            for j in 0..n {
                b.step()?;
                let prefix = arena.concat(last[i * n + k], looped, b)?;
                let via = arena.concat(prefix, last[k * n + j], b)?;
                next[i * n + j] = arena.union(last[i * n + j], via, b)?;
            }
        }
        core::mem::swap(&mut last, &mut next);
    }
    let mut language = EMPTY;
    for (i, row) in dfa.rows().enumerate() {
        b.step()?;
        let proof = arena.render(last[i], stack, text, b)?; // start row is always row 0.
        states.push(proof, b.limits.dfa_states, Limit::DfaStates)?;
        if row.accept {
            language = arena.union(language, last[i], b)?;
        }
    }
    let language = arena.render(language, stack, text, b)?;
    Ok(Proofs {
        states,
        text,
        language,
    })
}
