//! Bounded boolean BRE matching; locale effects stay behind an explicit context.
//! No captures are returned, so regular expressions need no leftmost-longest
//! capture selection. Backreferences still explore distinct capture histories.
mod machine;
mod parser;
#[cfg(test)]
mod tests;
use gnunet_native::locale::CharacterClass;
use std::{cmp::Ordering, fmt, io};

#[derive(Clone, Copy)]
pub(super) struct Limits {
    pub(super) pattern: usize,
    pub(super) input: usize,
    pub(super) instructions: usize,
    pub(super) states: usize,
    pub(super) work: usize,
    pub(super) nesting: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            pattern: 16384,
            input: 65536,
            instructions: 65536,
            states: 65536,
            work: 4_000_000,
            nesting: 64,
        }
    }
}
#[derive(Debug)]
pub(super) struct SyntaxError {
    at: usize,
    reason: &'static str,
}
impl fmt::Display for SyntaxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BRE syntax at character {}: {}", self.at, self.reason)
    }
}
impl std::error::Error for SyntaxError {}
pub(super) enum CompileError {
    Syntax(SyntaxError),
    Boundary(io::Error),
}
impl From<io::Error> for CompileError {
    fn from(error: io::Error) -> Self {
        Self::Boundary(error)
    }
}
fn syntax(at: usize, reason: &'static str) -> CompileError {
    CompileError::Syntax(SyntaxError { at, reason })
}
#[derive(Debug)]
pub(super) struct ResourceLimit(&'static str);
impl fmt::Display for ResourceLimit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BRE {} limit exceeded", self.0)
    }
}
impl std::error::Error for ResourceLimit {}
pub(super) fn limit(name: &'static str) -> io::Error {
    io::Error::other(ResourceLimit(name))
}
fn push<T>(values: &mut Vec<T>, value: T) -> io::Result<()> {
    values
        .try_reserve(1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    values.push(value);
    Ok(())
}
struct Budget {
    left: usize,
}
impl Budget {
    fn step(&mut self) -> io::Result<()> {
        self.spend(1)
    }
    fn spend(&mut self, units: usize) -> io::Result<()> {
        self.left = self.left.checked_sub(units).ok_or_else(|| limit("work"))?;
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub(super) enum Comparison {
    Collation,
    Primary,
}
pub(super) trait Context {
    fn classify(&self, symbol: u32, class: CharacterClass) -> io::Result<bool>;
    fn compare(&self, left: &[u32], right: &[u32], kind: Comparison) -> io::Result<Ordering>;
    fn collating_symbol(&self, value: &[u32]) -> io::Result<bool>;
    fn element_width(&self) -> usize;
    fn element_width_at(&self, first: u32) -> usize {
        let _ = first;
        self.element_width()
    }
}

#[derive(Clone, Copy)]
enum Assertion {
    Start,
    End,
    WordBoundary,
    NotWordBoundary,
    WordStart,
    WordEnd,
}
enum Element {
    Literal(u32),
    Class(CharacterClass),
    Collating(Vec<u32>),
    Equivalent(Vec<u32>),
    Range(Vec<u32>, Vec<u32>),
}
enum Matcher {
    Literal(u32),
    Any,
    Class {
        class: CharacterClass,
        polarity: Polarity,
    },
    Bracket {
        polarity: Polarity,
        elements: Vec<Element>,
        width: usize,
    },
}
#[derive(Clone, Copy, PartialEq)]
enum Polarity {
    Positive,
    Negative,
}
#[derive(Clone, Copy)]
enum Instruction {
    Consume(usize),
    Assert(Assertion),
    Save(usize),
    Reference(usize),
    Split(usize, usize),
    Jump(usize),
    Accept,
}
pub(super) struct Program {
    matchers: Vec<Matcher>,
    code: Vec<Instruction>,
    references: bool,
    limits: Limits,
}
impl Program {
    pub(super) fn compile(
        pattern: &[u32],
        context: &impl Context,
        limits: Limits,
    ) -> Result<Self, CompileError> {
        if pattern.len() > limits.pattern {
            return Err(limit("pattern").into());
        }
        let parsed = parser::parse(pattern, context, limits)?;
        let code = machine::compile(&parsed, limits)?;
        Ok(Self {
            matchers: parsed.matchers,
            code,
            references: parsed.references,
            limits,
        })
    }
    pub(super) fn matches(&self, input: &[u32], context: &impl Context) -> io::Result<bool> {
        if input.len() > self.limits.input {
            return Err(limit("input"));
        }
        machine::execute(self, input, context)
    }
}
