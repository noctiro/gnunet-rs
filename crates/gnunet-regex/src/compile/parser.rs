//! Iterative Thompson construction of the actual pinned byte grammar.
use super::{Budget, BuildError, Limit, push};
use alloc::vec::Vec;
const NONE: usize = usize::MAX;
pub(super) struct Node {
    pub head: usize,
}
pub(super) struct Arc {
    pub byte: Option<u8>,
    pub to: usize,
    pub next: usize,
}
pub(super) struct Nfa {
    pub nodes: Vec<Node>,
    pub arcs: Vec<Arc>,
    pub start: usize,
    pub end: usize,
}
#[derive(Clone, Copy)]
struct Fragment {
    start: usize,
    end: usize,
}
#[derive(Clone, Copy)]
struct Frame {
    atoms: usize,
    alternatives: usize,
}
impl Nfa {
    fn node(&mut self, b: &Budget) -> Result<usize, BuildError> {
        let i = self.nodes.len();
        push(
            &mut self.nodes,
            Node { head: NONE },
            b.limits.nfa_states,
            Limit::NfaStates,
        )?;
        Ok(i)
    }
    fn arc(
        &mut self,
        from: usize,
        to: usize,
        byte: Option<u8>,
        b: &Budget,
    ) -> Result<(), BuildError> {
        let i = self.arcs.len();
        push(
            &mut self.arcs,
            Arc {
                byte,
                to,
                next: self.nodes[from].head,
            },
            b.limits.nfa_transitions,
            Limit::NfaTransitions,
        )?;
        self.nodes[from].head = i;
        Ok(())
    }
}
fn pop(stack: &mut Vec<Fragment>, at: usize) -> Result<Fragment, BuildError> {
    stack.pop().ok_or(BuildError::Syntax { offset: at })
}
fn concat(
    n: &mut Nfa,
    stack: &mut Vec<Fragment>,
    at: usize,
    b: &mut Budget,
) -> Result<(), BuildError> {
    b.step()?;
    let right = pop(stack, at)?;
    let left = pop(stack, at)?;
    n.arc(left.end, right.start, None, b)?;
    push(
        stack,
        Fragment {
            start: left.start,
            end: right.end,
        },
        b.limits.stack,
        Limit::ParserStack,
    )
}
fn union(
    n: &mut Nfa,
    stack: &mut Vec<Fragment>,
    at: usize,
    b: &mut Budget,
) -> Result<(), BuildError> {
    b.step()?;
    let right = pop(stack, at)?;
    let left = pop(stack, at)?;
    let start = n.node(b)?;
    let end = n.node(b)?;
    n.arc(start, left.start, None, b)?;
    n.arc(start, right.start, None, b)?;
    n.arc(left.end, end, None, b)?;
    n.arc(right.end, end, None, b)?;
    push(
        stack,
        Fragment { start, end },
        b.limits.stack,
        Limit::ParserStack,
    )
}
pub(super) fn parse(input: &[u8], b: &mut Budget) -> Result<Nfa, BuildError> {
    if input.len() > b.limits.expression_bytes {
        return Err(BuildError::Limit(Limit::ExpressionBytes));
    }
    if input.is_empty() {
        return Err(BuildError::Syntax { offset: 0 });
    }
    let mut n = Nfa {
        nodes: Vec::new(),
        arcs: Vec::new(),
        start: 0,
        end: 0,
    };
    let mut stack = Vec::new();
    let mut frames = Vec::new();
    let mut current = Frame {
        atoms: 0,
        alternatives: 0,
    };
    for (at, byte) in input.iter().copied().enumerate() {
        b.step()?;
        match byte {
            0 => return Err(BuildError::Syntax { offset: at }),
            b'(' => {
                if current.atoms > 1 {
                    concat(&mut n, &mut stack, at, b)?;
                    current.atoms -= 1;
                }
                push(&mut frames, current, b.limits.stack, Limit::ParserStack)?;
                current = Frame {
                    atoms: 0,
                    alternatives: 0,
                };
            }
            b'|' => {
                if current.atoms == 0 {
                    return Err(BuildError::Syntax { offset: at });
                }
                while current.atoms > 1 {
                    concat(&mut n, &mut stack, at, b)?;
                    current.atoms -= 1;
                }
                current.atoms = 0;
                current.alternatives = current
                    .alternatives
                    .checked_add(1)
                    .ok_or(BuildError::Overflow)?;
            }
            b')' => {
                let outer = frames.pop().ok_or(BuildError::Syntax { offset: at })?;
                if current.atoms == 0 {
                    if current.alternatives != 0 {
                        return Err(BuildError::Syntax { offset: at });
                    }
                    current = outer; // The pinned parser ignores a genuinely empty group.
                    continue;
                }
                while current.atoms > 1 {
                    concat(&mut n, &mut stack, at, b)?;
                    current.atoms -= 1;
                }
                while current.alternatives > 0 {
                    union(&mut n, &mut stack, at, b)?;
                    current.alternatives -= 1;
                }
                current = outer;
                current.atoms = current.atoms.checked_add(1).ok_or(BuildError::Overflow)?;
            }
            b'*' | b'+' | b'?' => {
                if current.atoms == 0 {
                    return Err(BuildError::Syntax { offset: at });
                }
                let atom = pop(&mut stack, at)?;
                if byte == b'+' {
                    n.arc(atom.end, atom.start, None, b)?;
                    push(&mut stack, atom, b.limits.stack, Limit::ParserStack)?;
                } else {
                    let start = n.node(b)?;
                    let end = n.node(b)?;
                    n.arc(start, atom.start, None, b)?;
                    n.arc(start, end, None, b)?;
                    n.arc(atom.end, end, None, b)?;
                    if byte == b'*' {
                        n.arc(atom.end, atom.start, None, b)?;
                    }
                    push(
                        &mut stack,
                        Fragment { start, end },
                        b.limits.stack,
                        Limit::ParserStack,
                    )?;
                }
            }
            literal => {
                if current.atoms > 1 {
                    concat(&mut n, &mut stack, at, b)?;
                    current.atoms -= 1;
                }
                let start = n.node(b)?;
                let end = n.node(b)?;
                n.arc(start, end, Some(literal), b)?;
                push(
                    &mut stack,
                    Fragment { start, end },
                    b.limits.stack,
                    Limit::ParserStack,
                )?;
                current.atoms = current.atoms.checked_add(1).ok_or(BuildError::Overflow)?;
            }
        }
    }
    let at = input.len();
    if !frames.is_empty() || current.atoms == 0 {
        return Err(BuildError::Syntax { offset: at });
    }
    while current.atoms > 1 {
        concat(&mut n, &mut stack, at, b)?;
        current.atoms -= 1;
    }
    while current.alternatives > 0 {
        union(&mut n, &mut stack, at, b)?;
        current.alternatives -= 1;
    }
    let whole = pop(&mut stack, at)?;
    if !stack.is_empty() {
        return Err(BuildError::Syntax { offset: at });
    }
    n.start = whole.start;
    n.end = whole.end;
    Ok(n)
}
