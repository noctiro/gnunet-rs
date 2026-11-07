//! Finite subset construction and deterministic partition refinement.
use super::parser::Nfa;
use super::{Budget, BuildError, Limit, filled, push};
use alloc::vec::Vec;
#[derive(Clone, Copy)]
pub(super) struct Transition {
    pub byte: u8,
    pub to: usize,
}
pub(super) struct Row {
    pub accept: bool,
    pub edges: Vec<Transition>,
    subset: Vec<u64>,
}
pub(super) struct Dfa {
    pub rows: Vec<Row>,
}
fn contains(set: &[u64], i: usize) -> bool {
    set[i / 64] & (1u64 << (i % 64)) != 0
}
fn insert(set: &mut [u64], i: usize) -> bool {
    let old = contains(set, i);
    set[i / 64] |= 1u64 << (i % 64);
    !old
}
fn closure(
    n: &Nfa,
    set: &mut [u64],
    stack: &mut Vec<usize>,
    b: &mut Budget,
) -> Result<(), BuildError> {
    stack.clear();
    for i in 0..n.nodes.len() {
        b.step()?;
        if contains(set, i) {
            push(stack, i, b.limits.stack, Limit::ParserStack)?;
        }
    }
    while let Some(i) = stack.pop() {
        let mut edge = n.nodes[i].head;
        while edge != usize::MAX {
            b.step()?;
            let arc = &n.arcs[edge];
            if arc.byte.is_none() && insert(set, arc.to) {
                push(stack, arc.to, b.limits.stack, Limit::ParserStack)?;
            }
            edge = arc.next;
        }
    }
    Ok(())
}
fn copy_set(set: &[u64]) -> Result<Vec<u64>, BuildError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(set.len())
        .map_err(|_| BuildError::Allocation)?;
    copy.extend_from_slice(set);
    Ok(copy)
}
pub(super) fn determinize(n: Nfa, b: &mut Budget) -> Result<Dfa, BuildError> {
    let words = n.nodes.len().checked_add(63).ok_or(BuildError::Overflow)? / 64;
    if words > b.limits.subset_words {
        return Err(BuildError::Limit(Limit::SubsetWords));
    }
    let mut scratch = filled(words, 0u64)?;
    let mut stack = Vec::new();
    insert(&mut scratch, n.start);
    closure(&n, &mut scratch, &mut stack, b)?;
    let mut rows = Vec::new();
    push(
        &mut rows,
        Row {
            accept: contains(&scratch, n.end),
            edges: Vec::new(),
            subset: copy_set(&scratch)?,
        },
        b.limits.dfa_states,
        Limit::DfaStates,
    )?;
    let mut alphabet = [false; 256];
    for arc in &n.arcs {
        b.step()?;
        if let Some(byte) = arc.byte {
            alphabet[usize::from(byte)] = true;
        }
    }
    let mut total_edges = 0;
    let mut i = 0;
    while i < rows.len() {
        for (byte, present) in alphabet.iter().copied().enumerate().skip(1) {
            if !present {
                continue;
            }
            scratch.fill(0);
            let mut any = false;
            for node in 0..n.nodes.len() {
                b.step()?;
                if !contains(&rows[i].subset, node) {
                    continue;
                }
                let mut edge = n.nodes[node].head;
                while edge != usize::MAX {
                    b.step()?;
                    let arc = &n.arcs[edge];
                    if arc.byte == Some(byte as u8) {
                        insert(&mut scratch, arc.to);
                        any = true;
                    }
                    edge = arc.next;
                }
            }
            if !any {
                continue;
            }
            closure(&n, &mut scratch, &mut stack, b)?;
            let mut found = None;
            for (index, row) in rows.iter().enumerate() {
                let mut same = true;
                for (a, c) in row.subset.iter().zip(&scratch) {
                    b.step()?;
                    if a != c {
                        same = false;
                        break;
                    }
                }
                if same {
                    found = Some(index);
                    break;
                }
            }
            let target = match found {
                Some(index) => index,
                None => {
                    let next = rows
                        .len()
                        .checked_add(1)
                        .and_then(|n| n.checked_mul(words))
                        .ok_or(BuildError::Overflow)?;
                    if next > b.limits.subset_words {
                        return Err(BuildError::Limit(Limit::SubsetWords));
                    }
                    let target = rows.len();
                    push(
                        &mut rows,
                        Row {
                            accept: contains(&scratch, n.end),
                            edges: Vec::new(),
                            subset: copy_set(&scratch)?,
                        },
                        b.limits.dfa_states,
                        Limit::DfaStates,
                    )?;
                    target
                }
            };
            total_edges += 1;
            if total_edges > b.limits.transitions {
                return Err(BuildError::Limit(Limit::Transitions));
            }
            push(
                &mut rows[i].edges,
                Transition {
                    byte: byte as u8,
                    to: target,
                },
                b.limits.transitions,
                Limit::Transitions,
            )?;
        }
        i += 1;
    }
    Ok(Dfa { rows })
}
fn equivalent(a: &Row, c: &Row, classes: &[usize], b: &mut Budget) -> Result<bool, BuildError> {
    if a.accept != c.accept || a.edges.len() != c.edges.len() {
        return Ok(false);
    }
    for (left, right) in a.edges.iter().zip(&c.edges) {
        b.step()?;
        if left.byte != right.byte || classes[left.to] != classes[right.to] {
            return Ok(false);
        }
    }
    Ok(true)
}
pub(super) fn minimize(dfa: Dfa, b: &mut Budget) -> Result<Dfa, BuildError> {
    let n = dfa.rows.len();
    let mut classes = filled(n, 0usize)?;
    for (class, row) in classes.iter_mut().zip(&dfa.rows) {
        *class = usize::from(row.accept);
    }
    let mut next = filled(n, 0usize)?;
    let mut representatives = Vec::new();
    loop {
        representatives.clear();
        for i in 0..n {
            b.step()?;
            let mut found = None;
            for (class, representative) in representatives.iter().copied().enumerate() {
                b.step()?;
                if classes[i] == classes[representative]
                    && equivalent(&dfa.rows[i], &dfa.rows[representative], &classes, b)?
                {
                    found = Some(class);
                    break;
                }
            }
            next[i] = match found {
                Some(class) => class,
                None => {
                    let class = representatives.len();
                    push(&mut representatives, i, n, Limit::DfaStates)?;
                    class
                }
            };
        }
        if next == classes {
            break;
        }
        core::mem::swap(&mut next, &mut classes);
    }
    let mut rows = Vec::new();
    for representative in representatives {
        let original = &dfa.rows[representative];
        let mut edges = Vec::new();
        for edge in &original.edges {
            b.step()?;
            push(
                &mut edges,
                Transition {
                    byte: edge.byte,
                    to: classes[edge.to],
                },
                b.limits.transitions,
                Limit::Transitions,
            )?;
        }
        push(
            &mut rows,
            Row {
                accept: original.accept,
                edges,
                subset: Vec::new(),
            },
            b.limits.dfa_states,
            Limit::DfaStates,
        )?;
    }
    Ok(Dfa { rows })
}
