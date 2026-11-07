//! Exact source integer levels and native POSIX BRE callsite policy.
use crate::native::{Regex, RegexCompileFailure};
/// Original bit-valued error type, including unknown combinations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Level(pub i32);
impl Level {
    /// Unspecified global threshold.
    pub const UNSPECIFIED: Self = Self(-1);
    /// No ordinary messages.
    pub const NONE: Self = Self(0);
    /// Error bit.
    pub const ERROR: Self = Self(1);
    /// Warning bit.
    pub const WARNING: Self = Self(2);
    /// Ordinary user message bit.
    pub const MESSAGE: Self = Self(4);
    /// Informational bit.
    pub const INFO: Self = Self(8);
    /// Debug bit.
    pub const DEBUG: Self = Self(16);
    /// Source invalid-level value (it is still a nonnegative setup threshold).
    pub const INVALID: Self = Self(32);
    /// Repetition suppression modifier.
    pub const BULK: Self = Self(64);
    /// Source case-insensitive ASCII names; absent is unspecified.
    #[must_use]
    pub fn parse(value: Option<&[u8]>) -> Self {
        Self::parse_in(value, &gnunet_config::CaseSnapshot::C)
    }
    /// Same source level selection under an explicit native/C comparison profile.
    #[must_use]
    pub fn parse_in(value: Option<&[u8]>, profile: &gnunet_config::CaseSnapshot) -> Self {
        let Some(value) = value else {
            return Self::UNSPECIFIED;
        };
        let value = &value[..value.iter().position(|&b| b == 0).unwrap_or(value.len())];
        for level in [
            Self::DEBUG,
            Self::INFO,
            Self::MESSAGE,
            Self::WARNING,
            Self::ERROR,
            Self::NONE,
        ] {
            if profile.equals(value, level.name()) {
                return level;
            }
        }
        Self::INVALID
    }
    /// Source priority label for arbitrary bit combinations.
    #[must_use]
    pub fn name(self) -> &'static [u8] {
        for (bit, name) in [
            (1, b"ERROR".as_slice()),
            (2, b"WARNING"),
            (4, b"MESSAGE"),
            (8, b"INFO"),
            (16, b"DEBUG"),
        ] {
            if self.0 & bit != 0 {
                return name;
            }
        }
        if self.0 & !64 == 0 {
            b"NONE"
        } else {
            b"INVALID"
        }
    }
}
/// Fully identified source logging callsite.
#[derive(Clone, Copy, Debug)]
pub struct CallSite<'a> {
    /// None selects the current setup component without its PID.
    pub component: Option<&'a [u8]>,
    /// Native source filename bytes.
    pub file: &'a [u8],
    /// Source function name bytes.
    pub function: &'a [u8],
    /// Signed source line number.
    pub line: i32,
}
/// Exact source macro's initialized-once callsite status.
#[derive(Default, Debug)]
pub struct CallSiteCache(Option<bool>);
impl CallSiteCache {
    /// Empty cache, equivalent to GNUNET_LOG_CALL_STATUS=-1.
    #[must_use]
    pub fn new() -> Self {
        Self(None)
    }
    /// Explicit compile-profile constant status (zero or one).
    #[must_use]
    pub fn constant(enabled: bool) -> Self {
        Self(Some(enabled))
    }
    pub(crate) fn cached(
        &mut self,
        compute: impl FnOnce() -> std::io::Result<bool>,
    ) -> std::io::Result<bool> {
        if let Some(value) = self.0 {
            return Ok(value);
        }
        let value = compute()?;
        self.0 = Some(value);
        Ok(value)
    }
}
struct Definition {
    component: Regex,
    file: Regex,
    function: Regex,
    from: i32,
    to: i32,
    level: i32,
    force: bool,
}
/// Stateful parsed-once environment policy belonging to one logging owner.
pub struct Policy {
    minimum: Level,
    definitions: Vec<Definition>,
    parsed: bool,
    forced: bool,
    cases: gnunet_config::CaseContext,
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            minimum: Level::NONE,
            definitions: Vec::new(),
            parsed: false,
            forced: false,
            cases: gnunet_config::CaseContext::c(),
        }
    }
}
impl Policy {
    /// Select the same shared locale owner as PROGRAM/configuration. Existing
    /// parsed-once environment rules and static macro caches are not replayed.
    pub fn set_case_context(&mut self, context: gnunet_config::CaseContext) {
        self.cases = context;
    }
    /// Set a new explicit minimum; environment definitions are only captured once.
    /// Return raw parser diagnostics, separately routed to process stderr by caller.
    pub fn setup(
        &mut self,
        minimum: Option<&[u8]>,
        force: Option<&[u8]>,
        ordinary: Option<&[u8]>,
    ) -> std::io::Result<Vec<u8>> {
        let previous_minimum = self.minimum;
        self.minimum = Level::parse_in(minimum, &self.cases.snapshot());
        if self.parsed {
            return Ok(Vec::new());
        }
        let original_len = self.definitions.len();
        let previous_forced = self.forced;
        let result = self.setup_uncommitted(force, ordinary);
        match result {
            Ok(errors) => {
                self.parsed = true;
                Ok(errors)
            }
            Err(error) => {
                // A resource boundary did not complete this initialization.
                // Drop only this attempt's native regex owners before allowing
                // a real retry; never replay an already committed prefix.
                self.definitions.truncate(original_len);
                self.forced = previous_forced;
                self.minimum = previous_minimum;
                Err(error)
            }
        }
    }
    fn setup_uncommitted(
        &mut self,
        force: Option<&[u8]>,
        ordinary: Option<&[u8]>,
    ) -> std::io::Result<Vec<u8>> {
        let mut errors = Vec::new();
        if let Some(value) = force {
            self.forced = self.parse(value, true, &mut errors)? != 0;
        }
        if let Some(value) = ordinary {
            self.parse(value, false, &mut errors)?;
        }
        Ok(errors)
    }
    /// Source first-match threshold, before macro debug-culling and skip logic.
    pub fn enabled(
        &self,
        level: Level,
        default_component: &[u8],
        site: CallSite<'_>,
    ) -> std::io::Result<bool> {
        let caller = level.0;
        if self.minimum.0 >= 0 && !self.forced {
            return Ok(caller <= self.minimum.0);
        }
        for definition in &self.definitions {
            if (self.minimum.0 < 0 || definition.force)
                && site.line >= definition.from
                && site.line <= definition.to
                && definition
                    .component
                    .matches(site.component.unwrap_or(default_component))?
                && definition.file.matches(site.file)?
                && definition.function.matches(site.function)?
            {
                return Ok(caller <= definition.level);
            }
        }
        Ok(caller
            <= if self.minimum.0 >= 0 {
                self.minimum.0
            } else {
                Level::MESSAGE.0
            })
    }
    /// Number of successfully committed definitions, including a valid prefix of malformed input.
    #[must_use]
    pub fn definitions(&self) -> usize {
        self.definitions.len()
    }
    fn parse(&mut self, value: &[u8], force: bool, errors: &mut Vec<u8>) -> std::io::Result<usize> {
        let value = &value[..value.iter().position(|&b| b == 0).unwrap_or(value.len())];
        let mut bytes = value.to_vec();
        bytes.push(0);
        let mut state = 0usize;
        let mut start = 0;
        let mut component = 0;
        let mut file = 0;
        let mut function = 0;
        let mut range = (0, i32::MAX);
        let mut count = 0;
        for position in 0..bytes.len() {
            match bytes[position] {
                b';' => {
                    bytes[position] = 0;
                    match state {
                        0 => component = start,
                        1 => file = start,
                        2 => function = start,
                        3 => {
                            let Some(parsed) =
                                line_range(&bytes[start..position], &self.cases.snapshot())
                            else {
                                return Ok(count);
                            };
                            range = parsed;
                        }
                        _ => syntax(errors, &bytes[position..]),
                    }
                    start = position + 1;
                    state += 1;
                }
                0 | b'/' => {
                    if state != 4 {
                        syntax(errors, &bytes[position..]);
                        continue;
                    }
                    bytes[position] = 0;
                    state = 0;
                    let level =
                        Level::parse_in(Some(&bytes[start..position]), &self.cases.snapshot());
                    if level == Level::INVALID || level == Level::UNSPECIFIED {
                        return Ok(count);
                    }
                    let text = |offset| {
                        let tail = &bytes[offset..];
                        &tail[..tail.iter().position(|&b| b == 0).unwrap_or(tail.len())]
                    };
                    let regex = |value: &[u8]| -> std::io::Result<Option<Regex>> {
                        match Regex::new(if value.is_empty() { b".*" } else { value }) {
                            Ok(regex) => Ok(Some(regex)),
                            Err(RegexCompileFailure::InvalidPattern(status)) => {
                                debug_assert_ne!(status, 0);
                                Ok(None)
                            }
                            Err(RegexCompileFailure::Boundary(error)) => Err(error),
                        }
                    };
                    let Some(component) = regex(text(component))? else {
                        return Ok(count);
                    };
                    let Some(file) = regex(text(file))? else {
                        return Ok(count);
                    };
                    let Some(function) = regex(text(function))? else {
                        return Ok(count);
                    };
                    self.definitions.push(Definition {
                        component,
                        file,
                        function,
                        from: range.0,
                        to: range.1,
                        level: level.0,
                        force,
                    });
                    count += 1;
                    start = position + 1;
                }
                _ => {}
            }
        }
        Ok(count)
    }
}
fn line_range(input: &[u8], profile: &gnunet_config::CaseSnapshot) -> Option<(i32, i32)> {
    if input.is_empty() {
        return Some((0, i32::MAX));
    }
    let (value, end) = signed_decimal(input, profile)?;
    let from = value as i32;
    if from < 0 {
        return None;
    }
    if input.get(end) == Some(&b'-') {
        let (value, tail) = signed_decimal(&input[end + 1..], profile)?;
        let to = value as i32;
        if to < 0 || end + 1 + tail != input.len() {
            return None;
        }
        Some((from, to))
    } else {
        Some((from, from))
    }
}
fn signed_decimal(bytes: &[u8], profile: &gnunet_config::CaseSnapshot) -> Option<(i64, usize)> {
    let mut index = 0;
    while bytes
        .get(index)
        .is_some_and(|&value| profile.is_space(value))
    {
        index += 1;
    }
    let negative = bytes.get(index) == Some(&b'-');
    if negative || bytes.get(index) == Some(&b'+') {
        index += 1;
    }
    let start = index;
    let mut value = 0u64;
    while let Some(byte @ b'0'..=b'9') = bytes.get(index) {
        value = value.checked_mul(10)?.checked_add(u64::from(byte - b'0'))?;
        index += 1;
    }
    // strtol permits no digits, with endptr at the original start.
    if index == start {
        return Some((0, 0));
    }
    if negative {
        let signed = if value == 1u64 << 63 {
            i64::MIN
        } else {
            i64::try_from(value).ok()?.checked_neg()?
        };
        Some((signed, index))
    } else {
        Some((i64::try_from(value).ok()?, index))
    }
}

fn syntax(errors: &mut Vec<u8>, remaining: &[u8]) {
    errors.extend_from_slice(b"ERROR: Unable to parse log definition: Syntax error at `");
    errors.extend_from_slice(
        &remaining[..remaining
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(remaining.len())],
    );
    errors.extend_from_slice(b"'.\n");
}

#[cfg(test)]
mod boundary_tests {
    use super::CallSiteCache;
    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Resource failure is not a cached callsite decision and the following successful observation is independently asserted"
    )]
    fn native_failure_leaves_original_callsite_cache_uninitialized() -> std::io::Result<()> {
        let mut cache = CallSiteCache::new();
        let mut calls = 0;
        assert!(
            cache
                .cached(|| {
                    calls += 1;
                    Err(std::io::ErrorKind::OutOfMemory.into())
                })
                .is_err()
        );
        assert!(cache.cached(|| {
            calls += 1;
            Ok(true)
        })?);
        assert!(cache.cached(|| {
            calls += 1;
            Err(std::io::Error::other("should not run a third time"))
        })?);
        assert_eq!(calls, 2);
        Ok(())
    }
}
