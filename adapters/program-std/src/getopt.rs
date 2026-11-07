//! Byte-preserving table-driven public GETOPT engine and callback ownership.
use std::{
    ffi::OsString,
    io,
    os::unix::ffi::{OsStrExt, OsStringExt},
    rc::Rc,
};
/// Original descriptor argument mode; optional long arguments retain the source
/// wrapper's required-short-argument behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Argument {
    /// No argument.
    None,
    /// Required argument.
    Required,
    /// Optional long argument (short spelling still requires one).
    Optional,
}
/// Public metadata, separate from the uniquely borrowed processor/cleaner.
#[derive(Clone, Debug)]
pub struct Spec<'a> {
    /// Native short-name byte, including zero for a long-only descriptor.
    pub short: u8,
    /// Long spelling without leading dashes.
    pub name: &'a [u8],
    /// Optional help placeholder.
    pub argument_help: Option<&'a [u8]>,
    /// Help description; None terminates help formatting, as in the C descriptor.
    pub description: Option<&'a [u8]>,
    /// Original argument requirement.
    pub argument: Argument,
    /// Presence is checked after successful processing only.
    pub mandatory: bool,
    /// Must be the only matched option, including duplicate occurrences.
    pub exclusive: bool,
}
/// Synchronous callback view of the currently permuted command line.
#[derive(Clone, Copy, Debug)]
pub struct Context<'a> {
    /// Original `argv[0]` C-string prefix.
    pub binary_name: &'a [u8],
    /// Caller binaryOptions summary.
    pub binary_options: &'a [u8],
    /// Complete metadata in caller table order.
    pub options: &'a [Spec<'a>],
    /// Current partially permuted argv.
    pub argv: &'a [Vec<u8>],
    /// Source GNoptind-1, including consumed value arguments.
    pub current_argument: usize,
}
/// Separated process stdout/stderr bytes, without format-string interpretation.
pub struct Output<'observer> {
    /// Bytes for stdout.
    pub stdout: Vec<u8>,
    /// Bytes for stderr.
    pub stderr: Vec<u8>,
    /// Actual backend/format failure. An enabled NLS failure never becomes a
    /// successful English fallback; the owning parser/PROGRAM must stop.
    pub failure: Option<io::Error>,
    translation: Rc<dyn crate::locale::Translations>,
    configuration_observer: Option<gnunet_config::diagnostic::BorrowedObserver<'observer>>,
}
impl Default for Output<'_> {
    fn default() -> Self {
        Self::translated(crate::locale::disabled())
    }
}
impl std::fmt::Debug for Output<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Output")
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}
impl<'observer> Output<'observer> {
    /// Select an actual translation backend for official helper callbacks.
    pub fn translated(translation: Rc<dyn crate::locale::Translations>) -> Self {
        Self {
            stdout: Vec::new(),
            stderr: Vec::new(),
            failure: None,
            translation,
            configuration_observer: None,
        }
    }
    /// Borrowed synchronous CONFIG diagnostics for the current option run only.
    /// The observer is removed before the returned owned Run can escape.
    #[must_use]
    pub fn configuration_observer(
        &self,
    ) -> Option<gnunet_config::diagnostic::BorrowedObserver<'observer>> {
        self.configuration_observer
    }
    fn finish(self) -> Output<'static> {
        Output {
            stdout: self.stdout,
            stderr: self.stderr,
            failure: self.failure,
            translation: self.translation,
            configuration_observer: None,
        }
    }
    /// Translate a source template before typed safe rendering. None uses
    /// current textdomain; GNUnet's _ macro selects explicit domain gnunet.
    pub fn format(
        &self,
        domain: Option<&[u8]>,
        template: &[u8],
        arguments: &[crate::format::Argument<'_>],
    ) -> io::Result<Vec<u8>> {
        let translated = self.translation.gettext(domain, template)?;
        crate::format::render(&translated, arguments)
    }
    /// Append a translated official error, recording an actual failure instead
    /// of silently printing the untranslated template.
    pub fn error(&mut self, template: &[u8], arguments: &[crate::format::Argument<'_>]) -> bool {
        match self.format(Some(b"gnunet"), template, arguments) {
            Ok(bytes) => {
                self.stderr.extend_from_slice(&bytes);
                true
            }
            Err(error) => {
                self.failure = Some(error);
                false
            }
        }
    }
    /// Actual selected backend for source gettext help calls.
    #[must_use]
    pub fn translations(&self) -> Rc<dyn crate::locale::Translations> {
        Rc::clone(&self.translation)
    }
}
/// Option callback with original integer return semantics:1 continue,0 stop
/// successful processors,-1 failure. Other values remain observable source values.
pub trait Processor {
    /// Process the canonical long name and optional native value.
    fn process(
        &mut self,
        context: Context<'_>,
        name: &[u8],
        value: Option<&[u8]>,
        output: &mut Output,
    ) -> i32;
}
impl<F> Processor for F
where
    F: FnMut(Context<'_>, &[u8], Option<&[u8]>, &mut Output) -> i32,
{
    fn process(
        &mut self,
        context: Context<'_>,
        name: &[u8],
        value: Option<&[u8]>,
        output: &mut Output,
    ) -> i32 {
        self(context, name, value, output)
    }
}
struct Handler<'a> {
    processor: Box<dyn Processor + 'a>,
    cleaner: Option<Box<dyn FnOnce() + 'a>>,
}
/// Complete owned option descriptor returned by helper factories.
pub struct Definition<'a> {
    /// Readable metadata, including mandatory/exclusive modifiers.
    pub spec: Spec<'a>,
    handler: Handler<'a>,
}
impl<'a> Definition<'a> {
    /// Bind metadata to one uniquely owned processor.
    pub fn new(spec: Spec<'a>, processor: impl Processor + 'a) -> Self {
        Self {
            spec,
            handler: Handler {
                processor: Box::new(processor),
                cleaner: None,
            },
        }
    }
    pub(crate) fn process(
        &mut self,
        context: Context<'_>,
        name: &[u8],
        value: Option<&[u8]>,
        output: &mut Output,
    ) -> i32 {
        self.handler.processor.process(context, name, value, output)
    }
    /// Set the source mandatory flag without changing callback ownership.
    #[must_use]
    pub fn mandatory(mut self) -> Self {
        self.spec.mandatory = true;
        self
    }
    /// Set the source exclusive flag without changing callback ownership.
    #[must_use]
    pub fn exclusive(mut self) -> Self {
        self.spec.exclusive = true;
        self
    }
}
/// Consumed option table. Every cleaner runs exactly once on completion or unwind;
/// a freed C base32 closure cannot accidentally be reused through this owner.
#[derive(Default)]
pub struct Options<'a> {
    specs: Vec<Spec<'a>>,
    handlers: Vec<Handler<'a>>,
}
impl Drop for Options<'_> {
    fn drop(&mut self) {
        for handler in &mut self.handlers {
            if let Some(cleaner) = handler.cleaner.take() {
                cleaner();
            }
        }
    }
}
/// Source result plus the final permutation; code>0 is the first non-option index.
#[derive(Debug)]
pub struct Run {
    /// Original GETOPT integer status/index.
    pub code: i32,
    /// Final byte-preserving argv.
    pub argv: Vec<Vec<u8>>,
    /// Collected process output.
    pub output: Output<'static>,
}
impl Run {
    /// Remaining arguments only when code is a positive valid argv index.
    #[must_use]
    pub fn remaining(&self) -> Option<&[Vec<u8>]> {
        usize::try_from(self.code)
            .ok()
            .filter(|&v| v > 0)
            .and_then(|v| self.argv.get(v..))
    }
}
impl<'a> Options<'a> {
    /// New empty table, with no IO.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
    /// Append a descriptor and a uniquely owned callback. No implicit sorting occurs.
    pub fn push(&mut self, mut spec: Spec<'a>, processor: impl Processor + 'a) {
        spec.name = prefix(spec.name);
        spec.argument_help = spec.argument_help.map(prefix);
        spec.description = spec.description.map(prefix);
        self.specs.push(spec);
        self.handlers.push(Handler {
            processor: Box::new(processor),
            cleaner: None,
        });
    }
    /// Append a helper's complete owned descriptor.
    pub fn add(&mut self, mut definition: Definition<'a>) {
        definition.spec.name = prefix(definition.spec.name);
        definition.spec.argument_help = definition.spec.argument_help.map(prefix);
        definition.spec.description = definition.spec.description.map(prefix);
        self.specs.push(definition.spec);
        self.handlers.push(definition.handler);
    }
    /// Source PROGRAM option order: native toupper(short), then native signed char.
    /// Equal keys retain insertion order, one permitted order of C qsort ties.
    pub fn sort_program(&mut self) {
        let mut order = (0..self.specs.len()).collect::<Vec<_>>();
        order.sort_by_key(|&index| {
            let byte = self.specs[index].short;
            (crate::native::upper(byte), native_char(byte))
        });
        let mut slots = (0..order.len()).collect::<Vec<_>>();
        for (destination, &original) in order.iter().enumerate() {
            let current = slots.iter().position(|&value| value == original);
            if let Some(current) = current {
                self.specs.swap(destination, current);
                self.handlers.swap(destination, current);
                slots.swap(destination, current);
            }
        }
    }
    /// Attach a one-shot cleaner to the last registered descriptor.
    pub fn cleaner(&mut self, cleaner: impl FnOnce() + 'a) -> Result<(), gnunet_types::Error> {
        let last = self
            .handlers
            .last_mut()
            .ok_or(gnunet_types::Error::NotFound)?;
        if last.cleaner.is_some() {
            return Err(gnunet_types::Error::Conflict);
        }
        last.cleaner = Some(Box::new(cleaner));
        Ok(())
    }
    /// Inspect metadata before consuming this table.
    #[must_use]
    pub fn specs(&self) -> &[Spec<'a>] {
        &self.specs
    }
    /// Parse a native command line, retaining its source callback/diagnostic order.
    pub fn run(
        self,
        binary_options: &[u8],
        arguments: impl IntoIterator<Item = OsString>,
        posixly_correct: bool,
    ) -> Run {
        self.run_translated(
            binary_options,
            arguments,
            posixly_correct,
            crate::locale::disabled(),
        )
    }
    /// Same source parser with the selected PROGRAM gettext backend. The actual
    /// backend is retained by Output for every synchronous helper callback.
    pub fn run_translated(
        self,
        binary_options: &[u8],
        arguments: impl IntoIterator<Item = OsString>,
        posixly_correct: bool,
        translations: Rc<dyn crate::locale::Translations>,
    ) -> Run {
        self.run_translated_observed(
            binary_options,
            arguments,
            posixly_correct,
            translations,
            None,
        )
    }
    /// Run the same parser with immediate CONFIG diagnostics from filename
    /// helper callbacks. The observer is borrowed for this call, never stored in
    /// option handlers, filename targets or the owned returned output.
    pub fn run_translated_observed(
        mut self,
        binary_options: &[u8],
        arguments: impl IntoIterator<Item = OsString>,
        posixly_correct: bool,
        translations: Rc<dyn crate::locale::Translations>,
        observer: Option<gnunet_config::diagnostic::BorrowedObserver<'_>>,
    ) -> Run {
        let mut parser = Parser::new(
            arguments
                .into_iter()
                .map(|v| prefix(v.as_os_str().as_bytes()).to_vec())
                .collect(),
            &self.specs,
            posixly_correct,
        );
        let mut output = Output::translated(translations);
        output.configuration_observer = observer;
        if parser.argv.is_empty() {
            return Run {
                code: -1,
                argv: Vec::new(),
                output: output.finish(),
            };
        }
        let mut seen = vec![false; self.specs.len()];
        let mut continuation = 1;
        let mut matches = 0usize;
        let mut exclusive = None;
        while let Some(token) = parser.next(&mut output) {
            if output.failure.is_some() {
                continuation = -1;
                break;
            }
            if token.code == -1 {
                break;
            }
            if let Some(index) = token.descriptor.or_else(|| {
                self.specs
                    .iter()
                    .position(|s| native_char(s.short) == token.code)
            }) {
                matches += 1;
                let spec = &self.specs[index];
                if spec.exclusive {
                    exclusive = Some(prefix(spec.name));
                }
                if continuation == 1 {
                    let context = Context {
                        binary_name: &parser.argv[0],
                        binary_options: prefix(binary_options),
                        options: &self.specs,
                        argv: &parser.argv,
                        current_argument: parser.index.saturating_sub(1),
                    };
                    continuation = self.handlers[index].processor.process(
                        context,
                        prefix(spec.name),
                        token.value.as_deref(),
                        &mut output,
                    );
                }
                if output.failure.is_some() {
                    continuation = -1;
                    break;
                }
                seen[index] = true;
            } else {
                output.error(
                    b"Use %s to get a list of options.\n",
                    &[crate::format::Argument::Bytes(b"--help")],
                );
                continuation = -1;
            }
        }
        if let Some(name) = exclusive
            && matches > 1
            && output.failure.is_none()
        {
            output.error(
                b"Option `%s' can't be used with other options.\n",
                &[crate::format::Argument::Bytes(name)],
            );
            continuation = -1;
        }
        if continuation == 1 && output.failure.is_none() {
            for (index, spec) in self.specs.iter().enumerate() {
                if spec.mandatory && !seen[index] {
                    output.error(
                        b"Missing mandatory option `%s'.\n",
                        &[crate::format::Argument::Bytes(prefix(spec.name))],
                    );
                    continuation = -1;
                }
            }
        }
        let code = if output.failure.is_some() {
            -1
        } else if continuation == 1 {
            i32::try_from(parser.index).unwrap_or(-1)
        } else {
            continuation
        };
        Run {
            code,
            argv: std::mem::take(&mut parser.argv),
            output: output.finish(),
        }
    }
}
fn native_char(value: u8) -> i32 {
    value as libc::c_char as i32
}
fn prefix(value: &[u8]) -> &[u8] {
    &value[..value.iter().position(|&v| v == 0).unwrap_or(value.len())]
}
#[derive(Clone, Copy, Eq, PartialEq)]
enum Order {
    Permute,
    Require,
    Return,
}
struct Parser<'a> {
    argv: Vec<Vec<u8>>,
    specs: &'a [Spec<'a>],
    shorts: Vec<u8>,
    index: usize,
    first: usize,
    last: usize,
    next: Option<(usize, usize)>,
    order: Order,
    posix: bool,
    finished: bool,
    prefix: Option<u8>,
    initialized: bool,
}
struct Token {
    // An actual long-name match owns its original descriptor even when its
    // short spelling is zero or shared with another descriptor.
    descriptor: Option<usize>,
    code: i32,
    value: Option<Vec<u8>>,
}
impl<'a> Parser<'a> {
    fn new(argv: Vec<Vec<u8>>, specs: &'a [Spec<'a>], posix: bool) -> Self {
        let mut shorts = Vec::new();
        for spec in specs.iter().filter(|spec| spec.short != 0) {
            shorts.push(spec.short);
            if spec.argument != Argument::None {
                shorts.push(b':');
            }
        }
        let order = match shorts.first() {
            Some(b'-') => Order::Return,
            Some(b'+') => Order::Require,
            _ if posix => Order::Require,
            _ => Order::Permute,
        };
        let prefix = if matches!(shorts.first(), Some(b'-' | b'+')) {
            Some(shorts.remove(0))
        } else {
            None
        };
        Self {
            argv,
            specs,
            shorts,
            index: 1,
            first: 1,
            last: 1,
            next: None,
            order,
            posix,
            finished: false,
            prefix,
            initialized: false,
        }
    }
    fn exchange(&mut self) {
        self.argv[self.first..self.index].rotate_left(self.last - self.first);
        self.first += self.index - self.last;
        self.last = self.index;
    }
    fn nonoption(&self) -> bool {
        self.argv[self.index].first() != Some(&b'-') || self.argv[self.index].len() == 1
    }
    fn error(&self, output: &mut Output, body: &[&[u8]]) {
        use crate::format::Argument::{Bytes, Character};
        let argv = Bytes(&self.argv[0]);
        match body {
            [b"illegal option -- ", byte] => {
                output.error(b"%s: illegal option -- %c\n", &[argv, Character(byte[0])]);
            }
            [b"invalid option -- ", byte] => {
                output.error(b"%s: invalid option -- %c\n", &[argv, Character(byte[0])]);
            }
            [b"option requires an argument -- W"] => {
                output.error(
                    b"%s: option requires an argument -- %c\n",
                    &[argv, Character(b'W')],
                );
            }
            [b"option requires an argument -- ", byte] => {
                output.error(
                    b"%s: option requires an argument -- %c\n",
                    &[argv, Character(byte[0])],
                );
            }
            [b"option `-W ", name, b"' is ambiguous"] => {
                output.error(b"%s: option `-W %s' is ambiguous\n", &[argv, Bytes(name)]);
            }
            [b"option `-W ", name, b"' does not allow an argument"] => {
                output.error(
                    b"%s: option `-W %s' does not allow an argument\n",
                    &[argv, Bytes(name)],
                );
            }
            [b"option `--", name, b"' does not allow an argument"] => {
                output.error(
                    b"%s: option `--%s' does not allow an argument\n",
                    &[argv, Bytes(name)],
                );
            }
            [b"option `", name, b"' requires an argument"] => {
                output.error(
                    b"%s: option `%s' requires an argument\n",
                    &[argv, Bytes(name)],
                );
            }
            [b"option `", name, b"' is ambiguous"] => {
                output.error(b"%s: option `%s' is ambiguous\n", &[argv, Bytes(name)]);
            }
            [b"unrecognized option `", whole, b"'"] => {
                output.error(
                    b"%s: unrecognized option `--%s'\n",
                    &[argv, Bytes(whole.strip_prefix(b"--").unwrap_or(whole))],
                );
            }
            _ => {
                output.failure = Some(io::Error::other("unmapped source GETOPT diagnostic"));
            }
        }
    }
    fn next(&mut self, errors: &mut Output) -> Option<Token> {
        if self.finished {
            return None;
        }
        if self.initialized
            && let Some(prefix) = self.prefix.take()
        {
            self.shorts.insert(0, prefix);
        }
        self.initialized = true;
        if self
            .next
            .is_none_or(|(arg, offset)| offset >= self.argv[arg].len())
        {
            self.next = None;
            if self.order == Order::Permute {
                if self.first != self.last && self.last != self.index {
                    self.exchange();
                } else if self.last != self.index {
                    self.first = self.index;
                }
                while self.index < self.argv.len() && self.nonoption() {
                    self.index += 1;
                }
                self.last = self.index;
            }
            if self.index < self.argv.len() && self.argv[self.index] == b"--" {
                self.index += 1;
                if self.first != self.last && self.last != self.index {
                    self.exchange();
                } else if self.first == self.last {
                    self.first = self.index;
                }
                self.last = self.argv.len();
                self.index = self.argv.len();
            }
            if self.index == self.argv.len() {
                if self.first != self.last {
                    self.index = self.first;
                }
                self.finished = true;
                return None;
            }
            if self.nonoption() {
                if self.order == Order::Require {
                    self.finished = true;
                    return None;
                }
                let value = self.argv[self.index].clone();
                self.index += 1;
                return Some(Token {
                    descriptor: None,
                    code: 1,
                    value: Some(value),
                });
            }
            self.next = Some((
                self.index,
                if self.argv[self.index].get(1) == Some(&b'-') {
                    2
                } else {
                    1
                },
            ));
        }
        let (arg, offset) = self.next?;
        if self.argv[arg].get(1) == Some(&b'-') {
            let whole = self.argv[arg].clone();
            let text = &whole[offset..];
            self.next = None;
            self.index += 1;
            return Some(self.long(text, &whole, errors));
        }
        let byte = self.argv[arg][offset];
        let offset = offset + 1;
        self.next = Some((arg, offset));
        if offset == self.argv[arg].len() {
            self.index += 1;
        }
        let Some(short_index) = self
            .shorts
            .iter()
            .position(|&v| v == byte)
            .filter(|_| byte != b':')
        else {
            self.error(
                errors,
                &[
                    if self.posix {
                        b"illegal option -- "
                    } else {
                        b"invalid option -- "
                    },
                    &[byte],
                ],
            );
            return Some(Token {
                descriptor: None,
                code: i32::from(b'?'),
                value: None,
            });
        };
        if byte == b'W' && self.shorts.get(short_index + 1) == Some(&b';') {
            let Some(value) = self.required(arg, offset) else {
                self.error(errors, &[b"option requires an argument -- W"]);
                return Some(Token {
                    descriptor: None,
                    code: if self.shorts.first() == Some(&b':') {
                        i32::from(b':')
                    } else {
                        i32::from(b'?')
                    },
                    value: None,
                });
            };
            return Some(self.w_long(value, errors));
        }
        let mut value = None;
        if self.shorts.get(short_index + 1) == Some(&b':') {
            if self.shorts.get(short_index + 2) == Some(&b':') {
                if offset < self.argv[arg].len() {
                    value = Some(self.argv[arg][offset..].to_vec());
                    self.index += 1;
                }
                self.next = None;
            } else {
                value = self.required(arg, offset);
                if value.is_none() {
                    self.error(errors, &[b"option requires an argument -- ", &[byte]]);
                    return Some(Token {
                        descriptor: None,
                        code: if self.shorts.first() == Some(&b':') {
                            i32::from(b':')
                        } else {
                            i32::from(b'?')
                        },
                        value: None,
                    });
                }
            }
        }
        Some(Token {
            descriptor: None,
            code: native_char(byte),
            value,
        })
    }
    fn required(&mut self, arg: usize, offset: usize) -> Option<Vec<u8>> {
        self.next = None;
        if offset < self.argv[arg].len() {
            self.index += 1;
            Some(self.argv[arg][offset..].to_vec())
        } else if self.index < self.argv.len() {
            let value = self.argv[self.index].clone();
            self.index += 1;
            Some(value)
        } else {
            None
        }
    }
    fn w_long(&mut self, text: Vec<u8>, errors: &mut Output) -> Token {
        let split = text.iter().position(|&v| v == b'=');
        let name = &text[..split.unwrap_or(text.len())];
        let exact = self.specs.iter().position(|s| prefix(s.name) == name);
        let candidates = self
            .specs
            .iter()
            .enumerate()
            .filter(|(_, s)| prefix(s.name).starts_with(name))
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        let found = if let Some(index) = exact {
            index
        } else if candidates.len() == 1 {
            candidates[0]
        } else if candidates.len() > 1 {
            // The original GNU branch reads argv[index] for this diagnostic and
            // skips it. Terminal ambiguous -W may pass NULL to printf; this safe
            // owner supplies a literal boundary label and never reads past argv.
            let next = self
                .argv
                .get(self.index)
                .map(Vec::as_slice)
                .unwrap_or(b"(null)");
            self.error(errors, &[b"option `-W ", next, b"' is ambiguous"]);
            self.index = (self.index + 1).min(self.argv.len());
            return Token {
                descriptor: None,
                code: i32::from(b'?'),
                value: Some(text),
            };
        } else {
            return Token {
                descriptor: None,
                code: native_char(b'W'),
                value: Some(text),
            };
        };
        let spec = &self.specs[found];
        let mut value = Some(text.clone());
        if let Some(split) = split {
            if spec.argument == Argument::None {
                self.error(
                    errors,
                    &[
                        b"option `-W ",
                        prefix(spec.name),
                        b"' does not allow an argument",
                    ],
                );
                return Token {
                    descriptor: None,
                    code: i32::from(b'?'),
                    value: Some(text),
                };
            }
            value = Some(text[split + 1..].to_vec());
        } else if spec.argument == Argument::Required {
            if self.index == self.argv.len() {
                self.error(
                    errors,
                    &[
                        b"option `",
                        self.argv
                            .get(self.index.saturating_sub(1))
                            .map(Vec::as_slice)
                            .unwrap_or(b""),
                        b"' requires an argument",
                    ],
                );
                return Token {
                    descriptor: None,
                    code: if self.shorts.first() == Some(&b':') {
                        i32::from(b':')
                    } else {
                        i32::from(b'?')
                    },
                    value: Some(text),
                };
            }
            value = Some(self.argv[self.index].clone());
            self.index += 1;
        }
        Token {
            descriptor: Some(found),
            code: native_char(spec.short),
            value,
        }
    }
    fn long(&mut self, text: &[u8], whole: &[u8], errors: &mut Output) -> Token {
        let split = text.iter().position(|&v| v == b'=');
        let name = &text[..split.unwrap_or(text.len())];
        let found = self.specs.iter().position(|s| prefix(s.name) == name);
        let candidates = self
            .specs
            .iter()
            .enumerate()
            .filter(|(_, s)| prefix(s.name).starts_with(name))
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        let index = if let Some(found) = found {
            found
        } else if candidates.len() == 1 {
            candidates[0]
        } else if candidates.len() > 1 {
            self.error(errors, &[b"option `", whole, b"' is ambiguous"]);
            return Token {
                descriptor: None,
                code: i32::from(b'?'),
                value: None,
            };
        } else {
            self.error(errors, &[b"unrecognized option `", whole, b"'"]);
            return Token {
                descriptor: None,
                code: i32::from(b'?'),
                value: None,
            };
        };
        let spec = &self.specs[index];
        let mut value = None;
        if let Some(split) = split {
            if spec.argument == Argument::None {
                self.error(
                    errors,
                    &[
                        b"option `--",
                        prefix(spec.name),
                        b"' does not allow an argument",
                    ],
                );
                return Token {
                    descriptor: None,
                    code: i32::from(b'?'),
                    value: None,
                };
            }
            value = Some(text[split + 1..].to_vec());
        } else if spec.argument == Argument::Required {
            if self.index == self.argv.len() {
                self.error(errors, &[b"option `", whole, b"' requires an argument"]);
                return Token {
                    descriptor: None,
                    code: if self.shorts.first() == Some(&b':') {
                        i32::from(b':')
                    } else {
                        i32::from(b'?')
                    },
                    value: None,
                };
            }
            value = Some(self.argv[self.index].clone());
            self.index += 1;
        }
        Token {
            descriptor: Some(index),
            code: native_char(spec.short),
            value,
        }
    }
}
/// Append literal-space GNUNET_ARGS tokens, preserving tabs/quotes as ordinary bytes.
#[must_use]
pub fn append_environment(
    arguments: impl IntoIterator<Item = OsString>,
    environment: Option<&[u8]>,
) -> Vec<OsString> {
    let mut args = arguments.into_iter().collect::<Vec<_>>();
    if let Some(value) = environment {
        args.extend(
            prefix(value)
                .split(|&b| b == b' ')
                .filter(|v| !v.is_empty())
                .map(|v| OsString::from_vec(v.to_vec())),
        );
    }
    args
}

#[cfg(test)]
mod long_only_tests;
