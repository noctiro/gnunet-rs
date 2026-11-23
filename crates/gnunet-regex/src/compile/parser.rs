//! Iterative Thompson construction of the actual pinned byte grammar.
use super::{Budget, BuildError, Limit, storage::Buffer};

const NONE: usize = usize::MAX;

#[derive(Clone, Copy)]
pub(super) struct Node {
    pub head: usize,
}

#[derive(Clone, Copy)]
pub(super) struct Arc {
    pub byte: Option<u8>,
    pub to: usize,
    pub next: usize,
}

pub(super) struct Nfa<'a> {
    pub nodes: &'a [Node],
    pub arcs: &'a [Arc],
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

impl Frame {
    const EMPTY: Self = Self {
        atoms: 0,
        alternatives: 0,
    };
}

pub(super) struct Memory<const STATES: usize, const ARCS: usize, const STACK: usize> {
    nodes: [Node; STATES],
    arcs: [Arc; ARCS],
    stack: [Fragment; STACK],
    frames: [Frame; STACK],
}

impl<const STATES: usize, const ARCS: usize, const STACK: usize> Memory<STATES, ARCS, STACK> {
    pub(super) const fn new() -> Self {
        Self {
            nodes: [Node { head: 0 }; STATES],
            arcs: [Arc {
                byte: None,
                to: 0,
                next: 0,
            }; ARCS],
            stack: [Fragment { start: 0, end: 0 }; STACK],
            frames: [Frame::EMPTY; STACK],
        }
    }

    pub(super) fn workspace(&mut self) -> Workspace<'_> {
        Workspace {
            nodes: Buffer::fixed(&mut self.nodes),
            arcs: Buffer::fixed(&mut self.arcs),
            stack: Buffer::fixed(&mut self.stack),
            frames: Buffer::fixed(&mut self.frames),
        }
    }
}

pub(super) struct Workspace<'storage> {
    nodes: Buffer<'storage, Node>,
    arcs: Buffer<'storage, Arc>,
    stack: Buffer<'storage, Fragment>,
    frames: Buffer<'storage, Frame>,
}

impl Workspace<'_> {
    #[cfg(feature = "alloc")]
    pub(super) fn heap() -> Self {
        Self {
            nodes: Buffer::heap(),
            arcs: Buffer::heap(),
            stack: Buffer::heap(),
            frames: Buffer::heap(),
        }
    }

    pub(super) fn release(&mut self) {
        self.nodes.release();
        self.arcs.release();
        self.stack.release();
        self.frames.release();
    }
}

struct Construction<'work, 'storage> {
    nodes: &'work mut Buffer<'storage, Node>,
    arcs: &'work mut Buffer<'storage, Arc>,
}

impl Construction<'_, '_> {
    fn node(&mut self, b: &Budget) -> Result<usize, BuildError> {
        let i = self.nodes.len();
        self.nodes
            .push(Node { head: NONE }, b.limits.nfa_states, Limit::NfaStates)?;
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
        self.arcs.push(
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
fn pop(stack: &mut Buffer<'_, Fragment>, at: usize) -> Result<Fragment, BuildError> {
    stack.pop().ok_or(BuildError::Syntax { offset: at })
}
fn concat(
    n: &mut Construction<'_, '_>,
    stack: &mut Buffer<'_, Fragment>,
    at: usize,
    b: &mut Budget,
) -> Result<(), BuildError> {
    b.step()?;
    let right = pop(stack, at)?;
    let left = pop(stack, at)?;
    n.arc(left.end, right.start, None, b)?;
    stack.push(
        Fragment {
            start: left.start,
            end: right.end,
        },
        b.limits.stack,
        Limit::ParserStack,
    )
}
fn union(
    n: &mut Construction<'_, '_>,
    stack: &mut Buffer<'_, Fragment>,
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
    stack.push(Fragment { start, end }, b.limits.stack, Limit::ParserStack)
}
pub(super) fn parse<'work>(
    input: &[u8],
    workspace: &'work mut Workspace<'_>,
    b: &mut Budget,
) -> Result<Nfa<'work>, BuildError> {
    if input.len() > b.limits.expression_bytes {
        return Err(BuildError::Limit(Limit::ExpressionBytes));
    }
    if input.is_empty() {
        return Err(BuildError::Syntax { offset: 0 });
    }
    let Workspace {
        nodes,
        arcs,
        stack,
        frames,
    } = workspace;
    nodes.clear();
    arcs.clear();
    stack.clear();
    frames.clear();
    let mut n = Construction { nodes, arcs };
    let mut current = Frame::EMPTY;
    for (at, byte) in input.iter().copied().enumerate() {
        b.step()?;
        match byte {
            0 => return Err(BuildError::Syntax { offset: at }),
            b'(' => {
                if current.atoms > 1 {
                    concat(&mut n, stack, at, b)?;
                    current.atoms -= 1;
                }
                frames.push(current, b.limits.stack, Limit::ParserStack)?;
                current = Frame::EMPTY;
            }
            b'|' => {
                if current.atoms == 0 {
                    return Err(BuildError::Syntax { offset: at });
                }
                while current.atoms > 1 {
                    concat(&mut n, stack, at, b)?;
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
                    concat(&mut n, stack, at, b)?;
                    current.atoms -= 1;
                }
                while current.alternatives > 0 {
                    union(&mut n, stack, at, b)?;
                    current.alternatives -= 1;
                }
                current = outer;
                current.atoms = current.atoms.checked_add(1).ok_or(BuildError::Overflow)?;
            }
            b'*' | b'+' | b'?' => {
                if current.atoms == 0 {
                    return Err(BuildError::Syntax { offset: at });
                }
                let atom = pop(stack, at)?;
                if byte == b'+' {
                    n.arc(atom.end, atom.start, None, b)?;
                    stack.push(atom, b.limits.stack, Limit::ParserStack)?;
                } else {
                    let start = n.node(b)?;
                    let end = n.node(b)?;
                    n.arc(start, atom.start, None, b)?;
                    n.arc(start, end, None, b)?;
                    n.arc(atom.end, end, None, b)?;
                    if byte == b'*' {
                        n.arc(atom.end, atom.start, None, b)?;
                    }
                    stack.push(Fragment { start, end }, b.limits.stack, Limit::ParserStack)?;
                }
            }
            literal => {
                if current.atoms > 1 {
                    concat(&mut n, stack, at, b)?;
                    current.atoms -= 1;
                }
                let start = n.node(b)?;
                let end = n.node(b)?;
                n.arc(start, end, Some(literal), b)?;
                stack.push(Fragment { start, end }, b.limits.stack, Limit::ParserStack)?;
                current.atoms = current.atoms.checked_add(1).ok_or(BuildError::Overflow)?;
            }
        }
    }
    let at = input.len();
    if !frames.is_empty() || current.atoms == 0 {
        return Err(BuildError::Syntax { offset: at });
    }
    while current.atoms > 1 {
        concat(&mut n, stack, at, b)?;
        current.atoms -= 1;
    }
    while current.alternatives > 0 {
        union(&mut n, stack, at, b)?;
        current.alternatives -= 1;
    }
    let whole = pop(stack, at)?;
    if !stack.is_empty() {
        return Err(BuildError::Syntax { offset: at });
    }
    Ok(Nfa {
        nodes: n.nodes,
        arcs: n.arcs,
        start: whole.start,
        end: whole.end,
    })
}
