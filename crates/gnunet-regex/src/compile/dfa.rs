//! Bounded subset construction and deterministic partition refinement.

use super::{Budget, BuildError, Limit, parser::Nfa, storage::Buffer};

#[derive(Clone, Copy)]
pub(super) struct Transition {
    pub byte: u8,
    pub to: usize,
}

#[derive(Clone, Copy)]
struct RowHeader {
    accept: bool,
    first: usize,
    end: usize,
}

impl RowHeader {
    const EMPTY: Self = Self::new(false);

    const fn new(accept: bool) -> Self {
        Self {
            accept,
            first: 0,
            end: 0,
        }
    }

    fn view(self, edges: &[Transition]) -> Row<'_> {
        Row {
            accept: self.accept,
            edges: &edges[self.first..self.end],
        }
    }
}

pub(super) struct Row<'graph> {
    pub accept: bool,
    pub edges: &'graph [Transition],
}

pub(super) struct Graph<'graph> {
    rows: &'graph [RowHeader],
    edges: &'graph [Transition],
}

impl<'graph> Graph<'graph> {
    pub(super) const fn len(&self) -> usize {
        self.rows.len()
    }

    pub(super) fn row(&self, index: usize) -> Row<'graph> {
        self.rows[index].view(self.edges)
    }

    pub(super) fn rows(&self) -> impl ExactSizeIterator<Item = Row<'graph>> + '_ {
        self.rows.iter().map(|row| row.view(self.edges))
    }
}

#[derive(Clone, Copy)]
struct Partition {
    class: usize,
    next: usize,
    representative: usize,
}

impl Partition {
    const EMPTY: Self = Self {
        class: 0,
        next: 0,
        representative: 0,
    };
}

pub(super) struct Memory<
    const STATES: usize,
    const SUBSETS: usize,
    const EDGES: usize,
    const WORDS: usize,
    const STACK: usize,
> {
    rows: [RowHeader; STATES],
    edges: [Transition; EDGES],
    subsets: [u64; SUBSETS],
    candidate: [u64; WORDS],
    stack: [usize; STACK],
    partitions: [Partition; STATES],
}

impl<
    const STATES: usize,
    const SUBSETS: usize,
    const EDGES: usize,
    const WORDS: usize,
    const STACK: usize,
> Memory<STATES, SUBSETS, EDGES, WORDS, STACK>
{
    pub(super) const fn new() -> Self {
        Self {
            rows: [RowHeader::EMPTY; STATES],
            edges: [Transition { byte: 0, to: 0 }; EDGES],
            subsets: [0; SUBSETS],
            candidate: [0; WORDS],
            stack: [0; STACK],
            partitions: [Partition::EMPTY; STATES],
        }
    }

    pub(super) fn workspace(&mut self) -> Workspace<'_> {
        Workspace {
            rows: Buffer::fixed(&mut self.rows),
            edges: Buffer::fixed(&mut self.edges),
            subsets: Buffer::fixed(&mut self.subsets),
            candidate: Buffer::fixed(&mut self.candidate),
            stack: Buffer::fixed(&mut self.stack),
            partitions: Buffer::fixed(&mut self.partitions),
        }
    }
}

pub(super) struct Workspace<'storage> {
    rows: Buffer<'storage, RowHeader>,
    edges: Buffer<'storage, Transition>,
    subsets: Buffer<'storage, u64>,
    candidate: Buffer<'storage, u64>,
    stack: Buffer<'storage, usize>,
    partitions: Buffer<'storage, Partition>,
}

impl Workspace<'_> {
    #[cfg(feature = "alloc")]
    pub(super) fn heap() -> Self {
        Self {
            rows: Buffer::heap(),
            edges: Buffer::heap(),
            subsets: Buffer::heap(),
            candidate: Buffer::heap(),
            stack: Buffer::heap(),
            partitions: Buffer::heap(),
        }
    }

    pub(super) fn determinize(
        &mut self,
        nfa: Nfa<'_>,
        budget: &mut Budget,
    ) -> Result<Graph<'_>, BuildError> {
        self.rows.clear();
        self.edges.clear();
        self.subsets.clear();
        self.candidate.clear();

        let words = nfa.nodes.len().div_ceil(64);
        self.candidate
            .resize(words, 0, budget.limits.subset_words, Limit::SubsetWords)?;
        insert(&mut self.candidate, nfa.start);
        closure(&nfa, &mut self.candidate, &mut self.stack, budget)?;
        self.add_row(nfa.end, budget)?;

        let mut alphabet = [false; 256];
        for arc in nfa.arcs {
            budget.step()?;
            if let Some(byte) = arc.byte {
                alphabet[usize::from(byte)] = true;
            }
        }

        let mut index = 0;
        while index < self.rows.len() {
            let first = self.edges.len();
            for (byte, present) in alphabet.iter().copied().enumerate().skip(1) {
                if !present {
                    continue;
                }
                let byte = byte as u8;
                let subset = &self.subsets[index * words..][..words];
                if !successors(&nfa, subset, byte, &mut self.candidate, budget)? {
                    continue;
                }
                closure(&nfa, &mut self.candidate, &mut self.stack, budget)?;
                let to = match self.find_candidate(words, budget)? {
                    Some(existing) => existing,
                    None => self.add_row(nfa.end, budget)?,
                };
                self.edges.push(
                    Transition { byte, to },
                    budget.limits.transitions,
                    Limit::Transitions,
                )?;
            }
            self.rows[index].first = first;
            self.rows[index].end = self.edges.len();
            index += 1;
        }

        self.subsets.release();
        self.candidate.release();
        self.stack.release();
        self.minimize(budget)?;
        self.partitions.release();
        Ok(Graph {
            rows: &self.rows,
            edges: &self.edges,
        })
    }

    fn add_row(&mut self, accept: usize, budget: &Budget) -> Result<usize, BuildError> {
        let index = self.rows.len();
        self.subsets.extend_from_slice(
            &self.candidate,
            budget.limits.subset_words,
            Limit::SubsetWords,
        )?;
        self.rows.push(
            RowHeader::new(contains(&self.candidate, accept)),
            budget.limits.dfa_states,
            Limit::DfaStates,
        )?;
        Ok(index)
    }

    fn find_candidate(
        &self,
        words: usize,
        budget: &mut Budget,
    ) -> Result<Option<usize>, BuildError> {
        'row: for (index, row) in self.subsets.chunks_exact(words).enumerate() {
            for (member, candidate) in row.iter().zip(self.candidate.iter()) {
                budget.step()?;
                if member != candidate {
                    continue 'row;
                }
            }
            return Ok(Some(index));
        }
        Ok(None)
    }

    fn minimize(&mut self, budget: &mut Budget) -> Result<(), BuildError> {
        self.partitions.clear();
        self.partitions.resize(
            self.rows.len(),
            Partition::EMPTY,
            budget.limits.dfa_states,
            Limit::DfaStates,
        )?;
        for (partition, row) in self.partitions.iter_mut().zip(self.rows.iter()) {
            partition.class = usize::from(row.accept);
        }

        let class_count = loop {
            let mut count = 0;
            let mut same = true;
            for (index, row) in self.rows.iter().enumerate() {
                budget.step()?;
                let original = self.partitions[index].class;
                let mut found = None;
                for (class, partition) in self.partitions[..count].iter().enumerate() {
                    budget.step()?;
                    let representative = partition.representative;
                    if original == self.partitions[representative].class
                        && equivalent(
                            row.view(&self.edges),
                            self.rows[representative].view(&self.edges),
                            &self.partitions,
                            budget,
                        )?
                    {
                        found = Some(class);
                        break;
                    }
                }
                let class = if let Some(class) = found {
                    class
                } else {
                    self.partitions[count].representative = index;
                    count += 1;
                    count - 1
                };
                self.partitions[index].next = class;
                same &= class == original;
            }
            if same {
                break count;
            }
            for partition in self.partitions.iter_mut() {
                partition.class = partition.next;
            }
        };

        // Representatives are found in source order. Compact toward the start
        // of each table without overwriting any source not yet read.
        let mut end = 0;
        for (index, partition) in self.partitions[..class_count].iter().enumerate() {
            let row = self.rows[partition.representative];
            let first = end;
            for at in row.first..row.end {
                budget.step()?;
                let edge = self.edges[at];
                self.edges[end] = Transition {
                    byte: edge.byte,
                    to: self.partitions[edge.to].class,
                };
                end += 1;
            }
            self.rows[index] = RowHeader {
                accept: row.accept,
                first,
                end,
            };
        }
        self.rows.truncate(class_count);
        self.edges.truncate(end);
        Ok(())
    }
}

fn contains(set: &[u64], index: usize) -> bool {
    set[index / 64] & (1u64 << (index % 64)) != 0
}

fn insert(set: &mut [u64], index: usize) -> bool {
    let old = contains(set, index);
    set[index / 64] |= 1u64 << (index % 64);
    !old
}

fn closure(
    nfa: &Nfa<'_>,
    set: &mut [u64],
    stack: &mut Buffer<'_, usize>,
    budget: &mut Budget,
) -> Result<(), BuildError> {
    stack.clear();
    for index in 0..nfa.nodes.len() {
        budget.step()?;
        if contains(set, index) {
            stack.push(index, budget.limits.stack, Limit::ParserStack)?;
        }
    }
    while let Some(index) = stack.pop() {
        let mut edge = nfa.nodes[index].head;
        while edge != usize::MAX {
            budget.step()?;
            let arc = &nfa.arcs[edge];
            if arc.byte.is_none() && insert(set, arc.to) {
                stack.push(arc.to, budget.limits.stack, Limit::ParserStack)?;
            }
            edge = arc.next;
        }
    }
    Ok(())
}

fn successors(
    nfa: &Nfa<'_>,
    subset: &[u64],
    byte: u8,
    candidate: &mut [u64],
    budget: &mut Budget,
) -> Result<bool, BuildError> {
    candidate.fill(0);
    let mut any = false;
    for (index, node) in nfa.nodes.iter().enumerate() {
        budget.step()?;
        if !contains(subset, index) {
            continue;
        }
        let mut edge = node.head;
        while edge != usize::MAX {
            budget.step()?;
            let arc = &nfa.arcs[edge];
            if arc.byte == Some(byte) {
                insert(candidate, arc.to);
                any = true;
            }
            edge = arc.next;
        }
    }
    Ok(any)
}

fn equivalent(
    left: Row<'_>,
    right: Row<'_>,
    partitions: &[Partition],
    budget: &mut Budget,
) -> Result<bool, BuildError> {
    if left.accept != right.accept || left.edges.len() != right.edges.len() {
        return Ok(false);
    }
    for (left, right) in left.edges.iter().zip(right.edges) {
        budget.step()?;
        if left.byte != right.byte || partitions[left.to].class != partitions[right.to].class {
            return Ok(false);
        }
    }
    Ok(true)
}
