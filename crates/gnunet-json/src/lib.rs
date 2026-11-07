//! Bounded noalloc JSON values in caller-owned zeroizing scratch. Complete JSON
//! grammar is parsed iteratively, with finite token/nesting/byte/work budgets.
#![no_std]
#![forbid(unsafe_code)]
use core::fmt;
use gnunet_types::Error;
use zeroize::Zeroize;
mod parser;
mod real;
mod value;
pub use parser::{JsonString, Nest, Token};
pub use value::{Elements, Format, Member, Members, Value, ValueKind, string_len, write_string};
/// Finite JSON admission resources; caller buffers can impose smaller bounds.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum decoded/plain JSON bytes.
    pub bytes: usize,
    /// Maximum value/key metadata tokens.
    pub nodes: usize,
    /// Maximum containers, at most64 to bound all formatting recursion too.
    pub depth: usize,
    /// Maximum lexical/whitespace/duplicate-key comparison work steps.
    pub work: usize,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            bytes: 65535,
            nodes: 4096,
            depth: 64,
            work: 4_000_000,
        }
    }
}
impl Limits {
    fn validate(self) -> Result<(), Error> {
        if self.bytes == 0
            || self.nodes == 0
            || self.depth == 0
            || self.depth > 64
            || self.work == 0
        {
            return Err(Error::InvalidInput);
        }
        Ok(())
    }
}
/// Immutable document borrowed from its original exclusive workspace guard.
#[derive(Clone, Copy)]
pub struct Document<'a> {
    payload: &'a str,
    tokens: &'a [Token],
}
impl<'a> Document<'a> {
    /// Exact complete original JSON bytes, explicitly exposed while guard lives.
    pub fn expose_json(self) -> &'a [u8] {
        self.payload.as_bytes()
    }
    /// Original complete root, which can be any JSON value category.
    pub fn root(self) -> Value<'a> {
        Value {
            payload: self.payload,
            tokens: self.tokens,
            index: 0,
        }
    }
}
impl fmt::Debug for Document<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Document([REDACTED])")
    }
}
/// Exclusive caller-owned scratch. Initialization, every parse/provider/check
/// failure and Drop erase ALL payload/token/nesting storage. No heap is used.
pub struct Workspace<'a> {
    payload: &'a mut [u8],
    tokens: &'a mut [Token],
    stack: &'a mut [Nest],
}
impl<'a> Workspace<'a> {
    /// Bind caller buffers and erase their previous contents.
    pub fn new(payload: &'a mut [u8], tokens: &'a mut [Token], stack: &'a mut [Nest]) -> Self {
        let mut this = Self {
            payload,
            tokens,
            stack,
        };
        this.clear();
        this
    }
    /// Parse one complete caller input after finite copy/grammar validation.
    pub fn parse(&mut self, input: &[u8], limits: Limits) -> Result<Document<'_>, Error> {
        self.parse_with(
            |out| {
                let out = out.get_mut(..input.len()).ok_or(Error::Capacity)?;
                out.copy_from_slice(input);
                Ok(input.len())
            },
            limits,
        )
    }
    /// Decode/fill once into this original bounded scratch, then validate JSON.
    /// Provider error or returned length outside scratch erases the same owner.
    pub fn parse_with(
        &mut self,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
        limits: Limits,
    ) -> Result<Document<'_>, Error> {
        self.parse_with_check(fill, limits, |_| Ok(()))
    }
    /// Fill/parse and perform one caller semantic admission check BEFORE any
    /// document escapes. The check cannot return a borrowed document/value, and
    /// its failure erases original scratch. This preserves domain-specific caps
    /// without making JSON depend on REST, credentials, services or private keys.
    pub fn parse_with_check(
        &mut self,
        fill: impl FnOnce(&mut [u8]) -> Result<usize, Error>,
        limits: Limits,
        check: impl for<'b> FnOnce(Document<'b>) -> Result<(), Error>,
    ) -> Result<Document<'_>, Error> {
        self.clear();
        let result = (|| {
            limits.validate()?;
            let cap = self.payload.len().min(limits.bytes);
            let n = fill(&mut self.payload[..cap])?;
            if n > cap {
                return Err(Error::Capacity);
            }
            let nodes = self.tokens.len().min(limits.nodes);
            let depth = self.stack.len().min(limits.depth);
            let count = parser::parse(
                &self.payload[..n],
                &mut self.tokens[..nodes],
                &mut self.stack[..depth],
                limits.work,
            )?;
            let payload = core::str::from_utf8(&self.payload[..n]).map_err(|_| Error::Malformed)?;
            check(Document {
                payload,
                tokens: &self.tokens[..count],
            })?;
            Ok((n, count))
        })();
        let (n, count) = match result {
            Ok(v) => v,
            Err(e) => {
                self.clear();
                return Err(e);
            }
        };
        let payload = core::str::from_utf8(&self.payload[..n]).map_err(|_| Error::Malformed)?;
        Ok(Document {
            payload,
            tokens: &self.tokens[..count],
        })
    }
    /// Erase the full original buffers; live borrowed documents prevent reuse.
    pub fn clear(&mut self) {
        self.payload.zeroize();
        for token in self.tokens.iter_mut() {
            token.zeroize();
        }
        for nest in self.stack.iter_mut() {
            nest.zeroize();
        }
    }
}
impl Drop for Workspace<'_> {
    fn drop(&mut self) {
        self.clear();
    }
}
impl fmt::Debug for Workspace<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Workspace")
            .field("bytes", &self.payload.len())
            .field("nodes", &self.tokens.len())
            .field("depth", &self.stack.len())
            .finish_non_exhaustive()
    }
}
