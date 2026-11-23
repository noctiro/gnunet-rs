//! Bounded parser for GNU gettext's unsigned plural-expression grammar.
use std::io;

const MAX_EXPRESSION: usize = 1024;
const MAX_NODES: usize = 128;
const MAX_DEPTH: usize = 48;
const MAX_FORMS: u64 = 64;

fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid gettext plural expression",
    )
}

pub(super) struct Plural {
    expression: Option<Expression>,
}

struct Expression {
    nodes: Vec<Node>,
    root: usize,
    forms: u64,
}

impl Plural {
    pub(super) fn parse(metadata: &str) -> io::Result<Self> {
        let Some(body) = metadata.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("Plural-Forms").then_some(value)
        }) else {
            return Ok(Self { expression: None });
        };
        let mut forms = None;
        let mut expression = None;
        for assignment in body
            .split(';')
            .map(str::trim)
            .filter(|item| !item.is_empty())
        {
            let (name, value) = assignment.split_once('=').ok_or_else(invalid)?;
            match name.trim() {
                "nplurals" if forms.is_none() => {
                    forms = value
                        .trim()
                        .parse::<u64>()
                        .ok()
                        .filter(|n| (1..=MAX_FORMS).contains(n));
                    if forms.is_none() {
                        return Err(invalid());
                    }
                }
                "plural" if expression.is_none() => expression = Some(value.trim().as_bytes()),
                _ => return Err(invalid()),
            }
        }
        let forms = forms.ok_or_else(invalid)?;
        let input = expression
            .filter(|input| input.len() <= MAX_EXPRESSION)
            .ok_or_else(invalid)?;
        let mut parser = Parser {
            input,
            nodes: Vec::new(),
        };
        let root = parser.expression(0, 0)?;
        if !parser.input.trim_ascii().is_empty() {
            return Err(invalid());
        }
        Ok(Self {
            expression: Some(Expression {
                nodes: parser.nodes,
                root,
                forms,
            }),
        })
    }

    pub(super) fn index(&self, n: u64) -> Option<usize> {
        let Some(rule) = &self.expression else {
            return Some(usize::from(n != 1));
        };
        let result = rule.eval(rule.root, n)?;
        (result < rule.forms).then_some(result as usize)
    }
}

#[derive(Clone, Copy)]
enum Node {
    Count,
    Literal(u64),
    Not(usize),
    Negative(usize),
    Binary(Operator, usize, usize),
    Conditional(usize, usize, usize),
}

#[derive(Clone, Copy)]
enum Operator {
    Or,
    And,
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
}

const OPERATORS: &[(&[u8], Operator, u8)] = &[
    (b"||", Operator::Or, 1),
    (b"&&", Operator::And, 2),
    (b"==", Operator::Equal, 3),
    (b"!=", Operator::NotEqual, 3),
    (b"<=", Operator::LessEqual, 4),
    (b">=", Operator::GreaterEqual, 4),
    (b"<", Operator::Less, 4),
    (b">", Operator::Greater, 4),
    (b"+", Operator::Add, 5),
    (b"-", Operator::Subtract, 5),
    (b"*", Operator::Multiply, 6),
    (b"/", Operator::Divide, 6),
    (b"%", Operator::Modulo, 6),
];

struct Parser<'a> {
    input: &'a [u8],
    nodes: Vec<Node>,
}

impl Parser<'_> {
    fn push(&mut self, node: Node) -> io::Result<usize> {
        let index = self.nodes.len();
        if index == MAX_NODES {
            return Err(invalid());
        }
        self.nodes.push(node);
        Ok(index)
    }

    fn take(&mut self, text: u8) -> bool {
        self.input = self.input.trim_ascii_start();
        if let Some(rest) = self.input.strip_prefix(&[text]) {
            self.input = rest;
            true
        } else {
            false
        }
    }

    fn primary(&mut self, depth: usize) -> io::Result<usize> {
        if depth > MAX_DEPTH {
            return Err(invalid());
        }
        if self.take(b'(') {
            let value = self.expression(0, depth + 1)?;
            return self.take(b')').then_some(value).ok_or_else(invalid);
        }
        if self.take(b'!') {
            let value = self.primary(depth + 1)?;
            return self.push(Node::Not(value));
        }
        if self.take(b'-') {
            let value = self.primary(depth + 1)?;
            return self.push(Node::Negative(value));
        }
        if self.take(b'n') {
            return self.push(Node::Count);
        }
        let length = self
            .input
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count();
        let (digits, rest) = self.input.split_at(length);
        self.input = rest;
        let value = std::str::from_utf8(digits)
            .map_err(|_| invalid())?
            .parse()
            .map_err(|_| invalid())?;
        self.push(Node::Literal(value))
    }

    fn expression(&mut self, minimum: u8, depth: usize) -> io::Result<usize> {
        let mut left = self.primary(depth)?;
        loop {
            self.input = self.input.trim_ascii_start();
            let Some((text, op, precedence)) = OPERATORS
                .iter()
                .copied()
                .find(|(text, _, _)| self.input.starts_with(text))
            else {
                break;
            };
            if precedence < minimum {
                break;
            }
            self.input = &self.input[text.len()..];
            let right = self.expression(precedence + 1, depth + 1)?;
            left = self.push(Node::Binary(op, left, right))?;
        }
        if minimum == 0 && self.take(b'?') {
            let yes = self.expression(0, depth + 1)?;
            if !self.take(b':') {
                return Err(invalid());
            }
            let no = self.expression(0, depth + 1)?;
            left = self.push(Node::Conditional(left, yes, no))?;
        }
        Ok(left)
    }
}

impl Expression {
    fn eval(&self, index: usize, n: u64) -> Option<u64> {
        let operand = |node| self.eval(node, n);
        Some(match self.nodes[index] {
            Node::Count => n,
            Node::Literal(value) => value,
            Node::Not(value) => u64::from(operand(value)? == 0),
            Node::Negative(value) => operand(value)?.wrapping_neg(),
            Node::Conditional(condition, yes, no) => {
                operand(if operand(condition)? == 0 { no } else { yes })?
            }
            Node::Binary(op, left, right) => {
                let left = operand(left)?;
                match op {
                    Operator::Or => u64::from(left != 0 || operand(right)? != 0),
                    Operator::And => u64::from(left != 0 && operand(right)? != 0),
                    Operator::Equal => u64::from(left == operand(right)?),
                    Operator::NotEqual => u64::from(left != operand(right)?),
                    Operator::Less => u64::from(left < operand(right)?),
                    Operator::LessEqual => u64::from(left <= operand(right)?),
                    Operator::Greater => u64::from(left > operand(right)?),
                    Operator::GreaterEqual => u64::from(left >= operand(right)?),
                    Operator::Add => left.wrapping_add(operand(right)?),
                    Operator::Subtract => left.wrapping_sub(operand(right)?),
                    Operator::Multiply => left.wrapping_mul(operand(right)?),
                    Operator::Divide => left.checked_div(operand(right)?)?,
                    Operator::Modulo => left.checked_rem(operand(right)?)?,
                }
            }
        })
    }
}
