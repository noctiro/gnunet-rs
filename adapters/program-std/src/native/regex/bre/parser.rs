//! BRE grammar into a bounded arena; no recursive owned syntax tree is retained.
use super::{
    Assertion, CharacterClass, Comparison, CompileError, Context, Element, Limits, Matcher,
    Polarity, limit, push, syntax,
};
use std::{cmp::Ordering, io};
pub(super) enum Node {
    Sequence(Vec<usize>),
    Alternate(Vec<usize>),
    Consume(usize),
    Assert(Assertion),
    Group {
        body: usize,
        number: usize,
    },
    Reference(usize),
    Repeat {
        body: usize,
        minimum: usize,
        maximum: Option<usize>,
    },
}
pub(super) struct Parsed {
    pub(super) nodes: Vec<Node>,
    pub(super) matchers: Vec<Matcher>,
    pub(super) root: usize,
    pub(super) references: bool,
}
struct Parser<'a, C> {
    input: &'a [u32],
    at: usize,
    context: &'a C,
    limits: Limits,
    parsed: Parsed,
    groups: usize,
    closed: [bool; 9],
}
#[derive(Clone, Copy)]
enum Position {
    BranchStart,
    Inner,
}
pub(super) fn parse(
    input: &[u32],
    context: &impl Context,
    limits: Limits,
) -> Result<Parsed, CompileError> {
    let mut parser = Parser {
        input,
        at: 0,
        context,
        limits,
        groups: 0,
        closed: [false; 9],
        parsed: Parsed {
            nodes: Vec::new(),
            matchers: Vec::new(),
            root: 0,
            references: false,
        },
    };
    let root = parser.alternate(0)?;
    if parser.at != input.len() {
        return Err(syntax(parser.at, "unmatched group terminator"));
    }
    parser.parsed.root = root;
    Ok(parser.parsed)
}
impl<C: Context> Parser<'_, C> {
    fn node(&mut self, node: Node) -> Result<usize, CompileError> {
        if self.parsed.nodes.len() == self.limits.instructions {
            return Err(limit("syntax nodes").into());
        }
        let id = self.parsed.nodes.len();
        push(&mut self.parsed.nodes, node)?;
        Ok(id)
    }
    fn matcher(&mut self, matcher: Matcher) -> Result<usize, CompileError> {
        let id = self.parsed.matchers.len();
        push(&mut self.parsed.matchers, matcher)?;
        self.node(Node::Consume(id))
    }
    fn escaped(&self, byte: u8) -> bool {
        self.input.get(self.at..self.at.saturating_add(2))
            == Some(&[u32::from(b'\\'), u32::from(byte)])
    }
    fn take(&mut self) -> Result<u32, CompileError> {
        let unit = self
            .input
            .get(self.at)
            .copied()
            .ok_or_else(|| syntax(self.at, "unexpected end"))?;
        self.at += 1;
        Ok(unit)
    }
    fn alternate(&mut self, depth: usize) -> Result<usize, CompileError> {
        if depth > self.limits.nesting {
            return Err(limit("nesting").into());
        }
        let mut branches = Vec::new();
        loop {
            let sequence = self.sequence(depth)?;
            push(&mut branches, sequence)?;
            if !self.escaped(b'|') {
                break;
            }
            self.at += 2;
        }
        if branches.len() == 1 {
            Ok(branches[0])
        } else {
            self.node(Node::Alternate(branches))
        }
    }
    fn branch_end(&self) -> bool {
        self.at == self.input.len() || self.escaped(b')') || self.escaped(b'|')
    }
    fn sequence(&mut self, depth: usize) -> Result<usize, CompileError> {
        let mut sequence = Vec::new();
        while !self.branch_end() {
            let position = if sequence.is_empty() {
                Position::BranchStart
            } else {
                Position::Inner
            };
            let body = self.atom(position, depth)?;
            let node = if let Some((minimum, maximum)) = self.quantifier()? {
                if matches!(self.parsed.nodes[body], Node::Assert(_)) {
                    return Err(syntax(self.at, "assertion cannot be repeated"));
                }
                let node = self.node(Node::Repeat {
                    body,
                    minimum,
                    maximum,
                })?;
                if self.input.get(self.at) == Some(&u32::from(b'*'))
                    || self.escaped(b'+')
                    || self.escaped(b'?')
                    || self.escaped(b'{')
                {
                    return Err(syntax(self.at, "consecutive repetition operators"));
                }
                node
            } else {
                body
            };
            push(&mut sequence, node)?;
        }
        if sequence.len() == 1 {
            Ok(sequence[0])
        } else {
            self.node(Node::Sequence(sequence))
        }
    }
    fn atom(&mut self, position: Position, depth: usize) -> Result<usize, CompileError> {
        let at = self.at;
        let unit = self.take()?;
        match char::from_u32(unit) {
            Some('.') => self.matcher(Matcher::Any),
            Some('[') => self.bracket(),
            Some('^') if matches!(position, Position::BranchStart) => {
                self.node(Node::Assert(Assertion::Start))
            }
            Some('$') if self.branch_end() => self.node(Node::Assert(Assertion::End)),
            Some('\\') => self.escaped_atom(at, depth),
            _ => self.matcher(Matcher::Literal(unit)),
        }
    }
    fn escaped_atom(&mut self, at: usize, depth: usize) -> Result<usize, CompileError> {
        let unit = self.take()?;
        match char::from_u32(unit) {
            Some('(') => {
                self.groups += 1;
                let number = self.groups;
                let body = self.alternate(depth + 1)?;
                if !self.escaped(b')') {
                    return Err(syntax(at, "unclosed group"));
                }
                self.at += 2;
                if number <= 9 {
                    self.closed[number - 1] = true;
                }
                self.node(Node::Group { body, number })
            }
            Some(digit @ '1'..='9') => {
                let number = (u32::from(digit) - u32::from('1')) as usize;
                if !self.closed[number] {
                    return Err(syntax(at, "reference has no completed group"));
                }
                self.parsed.references = true;
                self.node(Node::Reference(number))
            }
            Some('{' | '+' | '?') => Err(syntax(at, "repetition has no operand")),
            Some('b') => self.node(Node::Assert(Assertion::WordBoundary)),
            Some('B') => self.node(Node::Assert(Assertion::NotWordBoundary)),
            Some('<') => self.node(Node::Assert(Assertion::WordStart)),
            Some('>') => self.node(Node::Assert(Assertion::WordEnd)),
            Some('`') => self.node(Node::Assert(Assertion::Start)),
            Some('\'') => self.node(Node::Assert(Assertion::End)),
            Some('s') => self.matcher(Matcher::Class {
                class: CharacterClass::Space,
                polarity: Polarity::Positive,
            }),
            Some('S') => self.matcher(Matcher::Class {
                class: CharacterClass::Space,
                polarity: Polarity::Negative,
            }),
            Some(word @ ('w' | 'W')) => {
                let mut elements = Vec::new();
                push(&mut elements, Element::Class(CharacterClass::Alnum))?;
                push(&mut elements, Element::Literal(u32::from(b'_')))?;
                self.matcher(Matcher::Bracket {
                    polarity: if word == 'w' {
                        Polarity::Positive
                    } else {
                        Polarity::Negative
                    },
                    elements,
                    width: 1,
                })
            }
            _ => self.matcher(Matcher::Literal(unit)),
        }
    }
    fn quantifier(&mut self) -> Result<Option<(usize, Option<usize>)>, CompileError> {
        if self.input.get(self.at) == Some(&u32::from(b'*')) {
            self.at += 1;
            return Ok(Some((0, None)));
        }
        if self.escaped(b'+') {
            self.at += 2;
            return Ok(Some((1, None)));
        }
        if self.escaped(b'?') {
            self.at += 2;
            return Ok(Some((0, Some(1))));
        }
        if !self.escaped(b'{') {
            return Ok(None);
        }
        self.at += 2;
        let minimum = self.number()?;
        let maximum = if self.input.get(self.at) == Some(&u32::from(b',')) {
            self.at += 1;
            if self.escaped(b'}') {
                None
            } else {
                Some(self.number()?)
            }
        } else {
            Some(minimum)
        };
        if !self.escaped(b'}') || maximum.is_some_and(|max| max < minimum) {
            return Err(syntax(self.at, "invalid repetition bounds"));
        }
        self.at += 2;
        Ok(Some((minimum, maximum)))
    }
    fn number(&mut self) -> Result<usize, CompileError> {
        let start = self.at;
        let mut number = 0usize;
        while let Some(digit) = self
            .input
            .get(self.at)
            .and_then(|n| n.checked_sub(48))
            .filter(|n| *n <= 9)
        {
            number = number * 10 + digit as usize;
            if number > 32767 {
                return Err(syntax(start, "repetition exceeds RE_DUP_MAX 32767"));
            }
            self.at += 1;
        }
        if self.at == start {
            return Err(syntax(start, "missing repetition count"));
        }
        Ok(number)
    }
    fn bracket(&mut self) -> Result<usize, CompileError> {
        let polarity = if self.input.get(self.at) == Some(&u32::from(b'^')) {
            self.at += 1;
            Polarity::Negative
        } else {
            Polarity::Positive
        };
        let mut elements = Vec::new();
        let mut width = if polarity == Polarity::Negative {
            self.context.element_width()
        } else {
            1
        };
        loop {
            if self.input.get(self.at) == Some(&u32::from(b']')) && !elements.is_empty() {
                self.at += 1;
                break;
            }
            let mut element = self.element()?;
            if self.input.get(self.at) == Some(&u32::from(b'-'))
                && self
                    .input
                    .get(self.at + 1)
                    .is_some_and(|n| *n != u32::from(b']'))
            {
                self.at += 1;
                let left = self.endpoint(element)?;
                let next = self.element()?;
                let right = self.endpoint(next)?;
                if self.context.compare(&left, &right, Comparison::Collation)? == Ordering::Greater
                {
                    return Err(syntax(self.at, "reversed collation range"));
                }
                width = width
                    .max(self.context.element_width())
                    .max(left.len())
                    .max(right.len());
                element = Element::Range(left, right);
            }
            match &element {
                Element::Collating(value) => width = width.max(value.len()),
                Element::Equivalent(value) => {
                    width = width.max(value.len()).max(self.context.element_width())
                }
                _ => {}
            }
            push(&mut elements, element)?;
        }
        self.matcher(Matcher::Bracket {
            polarity,
            elements,
            width,
        })
    }
    fn endpoint(&self, element: Element) -> Result<Vec<u32>, CompileError> {
        match element {
            Element::Literal(unit) => {
                let mut value = Vec::new();
                push(&mut value, unit)?;
                Ok(value)
            }
            Element::Collating(value) => Ok(value),
            _ => Err(syntax(
                self.at,
                "character class or equivalence used as range endpoint",
            )),
        }
    }
    fn element(&mut self) -> Result<Element, CompileError> {
        let start = self.at;
        let first = self.take()?;
        let Some(marker @ (46 | 58 | 61)) =
            self.input.get(self.at).copied().filter(|_| first == 91)
        else {
            return Ok(Element::Literal(first));
        };
        self.at += 1;
        let begin = self.at;
        while self.input.get(self.at..self.at.saturating_add(2)) != Some(&[marker, 93]) {
            self.take()?;
        }
        let name = &self.input[begin..self.at];
        self.at += 2;
        if name.is_empty() {
            return Err(syntax(start, "empty bracket name"));
        }
        if marker == 58 {
            let class = [
                (b"alnum".as_slice(), CharacterClass::Alnum),
                (b"alpha", CharacterClass::Alpha),
                (b"blank", CharacterClass::Blank),
                (b"cntrl", CharacterClass::Control),
                (b"digit", CharacterClass::Digit),
                (b"graph", CharacterClass::Graph),
                (b"lower", CharacterClass::Lower),
                (b"print", CharacterClass::Print),
                (b"punct", CharacterClass::Punct),
                (b"space", CharacterClass::Space),
                (b"upper", CharacterClass::Upper),
                (b"xdigit", CharacterClass::Hex),
            ]
            .into_iter()
            .find_map(|(text, class)| {
                (name.len() == text.len()
                    && name.iter().copied().eq(text.iter().copied().map(u32::from)))
                .then_some(class)
            })
            .ok_or_else(|| syntax(start, "unknown character class"))?;
            return Ok(Element::Class(class));
        }
        if name.len() > 64 {
            return Err(limit("collating symbol").into());
        }
        if !self.context.collating_symbol(name)? {
            return Err(syntax(start, "unknown collating symbol"));
        }
        let mut value = Vec::new();
        value
            .try_reserve_exact(name.len())
            .map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        value.extend_from_slice(name);
        Ok(if marker == 46 {
            Element::Collating(value)
        } else {
            Element::Equivalent(value)
        })
    }
}
