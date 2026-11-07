//! Bounded shared expression DAG for complete start-to-state languages.
//! Kleene matrix recurrence is the same language construction as the official
//! state proof algorithm; spelling is deliberately independent of C simplifier.
use super::dfa::Dfa;
use super::{Budget, BuildError, Limit, filled, push};
use alloc::vec::Vec;
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
struct Expr {
    kind: Kind,
    len: usize,
}
struct Arena {
    nodes: Vec<Expr>,
}
impl Arena {
    fn add(&mut self, kind: Kind, len: Option<usize>, b: &mut Budget) -> Result<usize, BuildError> {
        b.step()?;
        let len = len.ok_or(BuildError::Overflow)?;
        if len > b.limits.proof_bytes {
            return Err(BuildError::Limit(Limit::ProofBytes));
        }
        let id = self.nodes.len();
        push(
            &mut self.nodes,
            Expr { kind, len },
            b.limits.proof_nodes,
            Limit::ProofNodes,
        )?;
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
    fn render(&self, id: usize, b: &mut Budget) -> Result<Vec<u8>, BuildError> {
        enum Task {
            Node(usize),
            Byte(u8),
        }
        let mut output = Vec::new();
        output
            .try_reserve_exact(self.nodes[id].len)
            .map_err(|_| BuildError::Allocation)?;
        let mut stack = Vec::new();
        push(
            &mut stack,
            Task::Node(id),
            b.limits.stack,
            Limit::ParserStack,
        )?;
        while let Some(task) = stack.pop() {
            b.step()?;
            match task {
                Task::Byte(byte) => output.push(byte),
                Task::Node(node) => match self.nodes[node].kind {
                    Kind::Empty | Kind::Epsilon => {}
                    Kind::Byte(byte) => output.push(byte),
                    Kind::Concat(a, c) => {
                        push(
                            &mut stack,
                            Task::Node(c),
                            b.limits.stack,
                            Limit::ParserStack,
                        )?;
                        push(
                            &mut stack,
                            Task::Node(a),
                            b.limits.stack,
                            Limit::ParserStack,
                        )?;
                    }
                    Kind::Union(a, c) => {
                        for task in [
                            Task::Byte(b')'),
                            Task::Node(c),
                            Task::Byte(b'|'),
                            Task::Node(a),
                            Task::Byte(b'('),
                        ] {
                            push(&mut stack, task, b.limits.stack, Limit::ParserStack)?;
                        }
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
                            push(&mut stack, task, b.limits.stack, Limit::ParserStack)?;
                        }
                    }
                },
            }
        }
        if output.len() != self.nodes[id].len {
            return Err(BuildError::Overflow);
        }
        Ok(output)
    }
}
pub(super) fn create(dfa: &Dfa, b: &mut Budget) -> Result<(Vec<Vec<u8>>, Vec<u8>), BuildError> {
    let n = dfa.rows.len();
    let cells = n.checked_mul(n).ok_or(BuildError::Overflow)?;
    if cells > b.limits.matrix_cells {
        return Err(BuildError::Limit(Limit::MatrixCells));
    }
    let mut arena = Arena { nodes: Vec::new() };
    arena.add(Kind::Empty, Some(0), b)?;
    arena.add(Kind::Epsilon, Some(0), b)?;
    let mut literals = [EMPTY; 256];
    let mut last = filled(cells, EMPTY)?;
    let mut next = filled(cells, EMPTY)?;
    for (i, row) in dfa.rows.iter().enumerate() {
        for edge in &row.edges {
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
    let mut proofs = Vec::new();
    let mut total = 0usize;
    let mut language = EMPTY;
    for (i, row) in dfa.rows.iter().enumerate() {
        b.step()?;
        let proof = arena.render(last[i], b)?; // start row is always row0.
        total = total.checked_add(proof.len()).ok_or(BuildError::Overflow)?;
        if total > b.limits.total_proof_bytes {
            return Err(BuildError::Limit(Limit::TotalProofBytes));
        }
        push(&mut proofs, proof, b.limits.dfa_states, Limit::DfaStates)?;
        if row.accept {
            language = arena.union(language, last[i], b)?;
        }
    }
    let language = arena.render(language, b)?;
    total = total
        .checked_add(language.len())
        .ok_or(BuildError::Overflow)?;
    if total > b.limits.total_proof_bytes {
        return Err(BuildError::Limit(Limit::TotalProofBytes));
    }
    // No implicit copies of proof text are kept in the temporary DAG/matrices.
    Ok((proofs, language))
}
