//! Thompson instructions with memoized, bounded boolean search and capture histories.
use super::parser::{Node, Parsed};
use super::{
    Assertion, Budget, CharacterClass, Comparison, Context, Element, Instruction, Limits, Matcher,
    Polarity, Program, limit, push,
};
use std::{cmp::Ordering, collections::HashSet, hash::Hash, io, num::NonZeroUsize};

struct Compiler<'a> {
    parsed: &'a Parsed,
    code: Vec<Instruction>,
    limits: Limits,
    budget: Budget,
}
pub(super) fn compile(parsed: &Parsed, limits: Limits) -> io::Result<Vec<Instruction>> {
    let mut compiler = Compiler {
        parsed,
        code: Vec::new(),
        limits,
        budget: Budget { left: limits.work },
    };
    compiler.node(parsed.root)?;
    compiler.emit(Instruction::Accept)?;
    Ok(compiler.code)
}
impl Compiler<'_> {
    fn emit(&mut self, instruction: Instruction) -> io::Result<usize> {
        if self.code.len() == self.limits.instructions {
            return Err(limit("instructions"));
        }
        let position = self.code.len();
        push(&mut self.code, instruction)?;
        Ok(position)
    }
    fn node(&mut self, index: usize) -> io::Result<()> {
        self.budget.step()?;
        match &self.parsed.nodes[index] {
            Node::Consume(id) => {
                self.emit(Instruction::Consume(*id))?;
            }
            Node::Assert(assertion) => {
                self.emit(Instruction::Assert(*assertion))?;
            }
            Node::Reference(number) => {
                self.emit(Instruction::Reference(*number))?;
            }
            Node::Sequence(nodes) => {
                for node in nodes {
                    self.node(*node)?;
                }
            }
            Node::Alternate(branches) => {
                let mut ends = Vec::new();
                for (offset, branch) in branches.iter().enumerate() {
                    if offset + 1 == branches.len() {
                        self.node(*branch)?;
                        break;
                    }
                    let split = self.emit(Instruction::Split(0, 0))?;
                    let body = self.code.len();
                    self.node(*branch)?;
                    let jump = self.emit(Instruction::Jump(0))?;
                    push(&mut ends, jump)?;
                    self.code[split] = Instruction::Split(body, self.code.len());
                }
                for jump in ends {
                    self.code[jump] = Instruction::Jump(self.code.len());
                }
            }
            Node::Group { body, number } => {
                if self.parsed.references && *number <= 9 {
                    self.emit(Instruction::Save(2 * (number - 1)))?;
                    self.node(*body)?;
                    self.emit(Instruction::Save(2 * (number - 1) + 1))?;
                } else {
                    self.node(*body)?;
                }
            }
            Node::Repeat {
                body,
                minimum,
                maximum,
            } => {
                for _ in 0..*minimum {
                    self.node(*body)?;
                }
                if let Some(maximum) = maximum {
                    for _ in *minimum..*maximum {
                        let split = self.emit(Instruction::Split(0, 0))?;
                        let begin = self.code.len();
                        self.node(*body)?;
                        self.code[split] = Instruction::Split(self.code.len(), begin);
                    }
                } else {
                    let split = self.emit(Instruction::Split(0, 0))?;
                    let begin = self.code.len();
                    self.node(*body)?;
                    self.emit(Instruction::Jump(split))?;
                    self.code[split] = Instruction::Split(self.code.len(), begin);
                }
            }
        }
        Ok(())
    }
}
trait CaptureState: Default + Copy + Eq + Hash {
    fn save(&mut self, slot: usize, position: usize);
    fn reference(self, number: usize) -> Option<(usize, usize)>;
}
#[derive(Default, Clone, Copy, Eq, PartialEq, Hash)]
struct NoCaptures;
impl CaptureState for NoCaptures {
    fn save(&mut self, _: usize, _: usize) {}
    fn reference(self, _: usize) -> Option<(usize, usize)> {
        None
    }
}
#[derive(Default, Clone, Copy, Eq, PartialEq, Hash)]
struct Captures([Option<NonZeroUsize>; 18]);
impl CaptureState for Captures {
    fn save(&mut self, slot: usize, position: usize) {
        // An input Vec<u32> is bounded by isize::MAX bytes, so every valid
        // position plus one fits usize. The niche avoids doubling each slot.
        self.0[slot] = NonZeroUsize::new(position + 1);
    }
    fn reference(self, number: usize) -> Option<(usize, usize)> {
        Some((
            self.0[2 * number]?.get() - 1,
            self.0[2 * number + 1]?.get() - 1,
        ))
    }
}
#[derive(Clone, Copy, Eq, PartialEq, Hash)]
struct State<C> {
    pc: usize,
    position: usize,
    captures: C,
}
fn schedule<C: CaptureState>(
    stack: &mut Vec<State<C>>,
    state: State<C>,
    limits: Limits,
) -> io::Result<()> {
    if stack.len() == limits.states {
        return Err(limit("pending states"));
    }
    push(stack, state)
}
pub(super) fn execute(
    program: &Program,
    input: &[u32],
    context: &impl Context,
) -> io::Result<bool> {
    if program.references {
        search::<Captures>(program, input, context)
    } else {
        search::<NoCaptures>(program, input, context)
    }
}
fn search<C: CaptureState>(
    program: &Program,
    input: &[u32],
    context: &impl Context,
) -> io::Result<bool> {
    let mut seen = HashSet::new();
    let mut stack = Vec::new();
    let mut budget = Budget {
        left: program.limits.work,
    };
    for start in 0..=input.len() {
        schedule(
            &mut stack,
            State {
                pc: 0,
                position: start,
                captures: C::default(),
            },
            program.limits,
        )?;
        while let Some(mut state) = stack.pop() {
            budget.step()?;
            if seen.contains(&state) {
                continue;
            }
            if seen.len() == program.limits.states {
                return Err(limit("visited states"));
            }
            seen.try_reserve(1)
                .map_err(|_| io::ErrorKind::OutOfMemory)?;
            seen.insert(state);
            let instruction = program.code[state.pc];
            state.pc += 1;
            match instruction {
                Instruction::Accept => return Ok(true),
                Instruction::Jump(pc) => {
                    state.pc = pc;
                    schedule(&mut stack, state, program.limits)?;
                }
                Instruction::Split(first, second) => {
                    let mut alternative = state;
                    alternative.pc = second;
                    schedule(&mut stack, alternative, program.limits)?;
                    state.pc = first;
                    schedule(&mut stack, state, program.limits)?;
                }
                Instruction::Save(slot) => {
                    state.captures.save(slot, state.position);
                    schedule(&mut stack, state, program.limits)?;
                }
                Instruction::Assert(assertion) => {
                    if assertion.matches(input, state.position, context)? {
                        schedule(&mut stack, state, program.limits)?;
                    }
                }
                Instruction::Reference(number) => {
                    if let Some((begin, end)) = state.captures.reference(number)
                        && let Some(value) = input.get(begin..end)
                    {
                        budget.spend(value.len())?;
                        if input.get(state.position..state.position + value.len()) == Some(value) {
                            state.position += value.len();
                            schedule(&mut stack, state, program.limits)?;
                        }
                    }
                }
                Instruction::Consume(id) => {
                    let matcher = &program.matchers[id];
                    let remaining = input.len() - state.position;
                    let width = if let Some(first) = input.get(state.position) {
                        matcher
                            .width()
                            .min(context.element_width_at(*first))
                            .min(remaining)
                    } else {
                        0
                    };
                    if width == 0 {
                        continue;
                    }
                    let negative = matches!(
                        matcher,
                        Matcher::Bracket {
                            polarity: Polarity::Negative,
                            ..
                        }
                    );
                    let mut excluded = false;
                    let mut element_width = 1;
                    for count in 1..=width {
                        budget.spend(count)?;
                        if negative
                            && context
                                .collating_symbol(&input[state.position..state.position + count])?
                        {
                            element_width = count;
                        }
                        if matcher.matches(
                            &input[state.position..state.position + count],
                            context,
                            &mut budget,
                        )? {
                            if negative {
                                excluded = true;
                                break;
                            }
                            let mut next = state;
                            next.position += count;
                            schedule(&mut stack, next, program.limits)?;
                        }
                    }
                    if negative && !excluded {
                        state.position += element_width;
                        schedule(&mut stack, state, program.limits)?;
                    }
                }
            }
        }
    }
    Ok(false)
}
impl Matcher {
    fn width(&self) -> usize {
        if let Self::Bracket { width, .. } = self {
            *width
        } else {
            1
        }
    }
    fn matches(
        &self,
        value: &[u32],
        context: &impl Context,
        budget: &mut Budget,
    ) -> io::Result<bool> {
        match self {
            Self::Literal(unit) => Ok(value == [*unit]),
            Self::Any => Ok(value.len() == 1),
            Self::Class { class, polarity } => {
                Ok(context.classify(value[0], *class)? == (*polarity == Polarity::Positive))
            }
            Self::Bracket { elements, .. } => {
                for element in elements {
                    budget.step()?;
                    if element.matches(value, context, budget)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
}
impl Element {
    fn matches(
        &self,
        value: &[u32],
        context: &impl Context,
        budget: &mut Budget,
    ) -> io::Result<bool> {
        let cost = match self {
            Self::Literal(_) | Self::Class(_) => 1,
            Self::Collating(key) | Self::Equivalent(key) => value.len().saturating_add(key.len()),
            Self::Range(left, right) => value
                .len()
                .saturating_mul(2)
                .saturating_add(left.len())
                .saturating_add(right.len()),
        };
        budget.spend(cost)?;
        match self {
            Self::Literal(unit) => Ok(value == [*unit]),
            Self::Class(class) => Ok(value.len() == 1 && context.classify(value[0], *class)?),
            Self::Collating(key) => Ok(value.len() == key.len()
                && context.compare(value, key, Comparison::Collation)? == Ordering::Equal),
            Self::Equivalent(key) => Ok(context.collating_symbol(value)?
                && context.compare(value, key, Comparison::Primary)? == Ordering::Equal),
            Self::Range(left, right) => Ok(context.collating_symbol(value)?
                && context.compare(value, left, Comparison::Collation)? != Ordering::Less
                && context.compare(value, right, Comparison::Collation)? != Ordering::Greater),
        }
    }
}
impl Assertion {
    fn matches(self, input: &[u32], position: usize, context: &impl Context) -> io::Result<bool> {
        match self {
            Self::Start => return Ok(position == 0),
            Self::End => return Ok(position == input.len()),
            _ => {}
        }
        let word = |unit: Option<&u32>| -> io::Result<bool> {
            if let Some(unit) = unit {
                Ok(*unit == 95 || context.classify(*unit, CharacterClass::Alnum)?)
            } else {
                Ok(false)
            }
        };
        let before = word(position.checked_sub(1).and_then(|n| input.get(n)))?;
        let after = word(input.get(position))?;
        Ok(match self {
            Self::WordBoundary => before != after,
            Self::NotWordBoundary => before == after,
            Self::WordStart => !before && after,
            Self::WordEnd => before && !after,
            Self::Start | Self::End => false,
        })
    }
}
