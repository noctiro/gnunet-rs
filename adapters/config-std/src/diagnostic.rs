//! Synchronous source-derived diagnostic observations, separate from provenance.
//! No stdout/stderr, native locale or global logger is installed by configuration.
use std::sync::Arc;
/// Source bit-valued diagnostic severity (same values as GNUNET_ErrorType).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Level(pub i32);
impl Level {
    /// Source ERROR bit.
    pub const ERROR: Self = Self(1);
    /// Source WARNING bit.
    pub const WARNING: Self = Self(2);
    /// Source INFO bit.
    pub const INFO: Self = Self(8);
    /// Source DEBUG bit, observed even when a consumer compile profile culls it.
    pub const DEBUG: Self = Self(16);
}
/// Reviewed typed source format operand, borrowed only through one callback.
#[derive(Clone, Copy, Debug)]
pub enum Argument<'a> {
    /// Native byte-string prefix. Source diagnostics may include an invalid choice
    /// value; observers must treat this as configuration data, not a format.
    Bytes(&'a [u8]),
    /// Source unsigned scalar (line/count/size).
    Unsigned(u64),
    /// Source signed scalar.
    Signed(i64),
    /// Captured actual syscall errno, formatted under the consumer's active locale.
    Error(&'a std::io::Error),
    /// A nested source gettext operand, translated before the outer format.
    Translated {
        /// Explicit source dgettext domain.
        domain: &'static [u8],
        /// Untranslated message bytes.
        message: &'a [u8],
    },
    /// The C source supplies NULL to a%s format at this DEBUG-only site. Consumers
    /// must apply an explicit safe correction; no undefined C experiment is implied.
    NullString,
}
/// Exact logical source location. __FILE__ includes build-specific prefixes in C;
/// this records its pinned basename and function/line for explicit projection.
#[derive(Clone, Copy, Debug)]
pub struct Site {
    /// Stable macro-call identity for consumer first-call enabled caches.
    pub id: &'static str,
    /// Original source basename.
    pub file: &'static [u8],
    /// Original enclosing function.
    pub function: &'static [u8],
    /// Original macro invocation line.
    pub line: u32,
}
/// One original call-site observation, emitted before parser progress continues.
#[derive(Clone, Copy, Debug)]
pub struct Diagnostic<'a> {
    /// Original kind; consumer policy/cull/skip evaluation remains explicit.
    pub level: Level,
    /// Source log_from component or None for the current process component.
    pub component: Option<&'static [u8]>,
    /// Original macro location and cache identity.
    pub site: Site,
    /// Explicit dgettext domain for source _; None means the source literal is not translated.
    pub domain: Option<&'static [u8]>,
    /// Original printf template, used only by a reviewed safe typed renderer.
    pub template: &'static [u8],
    /// Synchronously borrowed operands; retaining them requires copying.
    pub arguments: &'a [Argument<'a>],
}
/// Shared explicit callback authority. Fn rather than FnMut keeps Configuration
/// Send+Sync; consumers needing mutation can use their own synchronized owner.
/// Callback execution is synchronous. It must not lock/re-enter the same externally
/// locked configuration owner. It receives no mutable configuration authority.
pub type Observer = Arc<dyn for<'a> Fn(Diagnostic<'a>) + Send + Sync>;

/// One operation's borrowed callback. A local callback replaces persistent
/// observation for that operation and nested files and is never stored.
pub type BorrowedObserver<'observer> = &'observer dyn for<'event> Fn(Diagnostic<'event>);

/// Borrowed callback data cannot escape the synchronous operation. Copying the
/// template/operands into owned bytes is the supported positive control.
///
/// ```compile_fail,E0521
/// use gnunet_config::{Configuration, diagnostic::Diagnostic};
/// let mut config = Configuration::default();
/// let escaped = std::cell::RefCell::new(None);
/// let observer = |event: Diagnostic<'_>| {
///     *escaped.borrow_mut() = Some(event.arguments);
/// };
/// drop(config.deserialize_observed(b"broken\n", None, Some(&observer)));
/// drop(escaped);
/// ```
///
/// ```
/// use gnunet_config::{Configuration, diagnostic::Diagnostic};
/// let mut config = Configuration::default();
/// let copied = std::cell::RefCell::new(Vec::new());
/// let observer = |event: Diagnostic<'_>| copied.borrow_mut().push(event.template.to_vec());
/// assert!(config.deserialize_observed(b"broken\n", None, Some(&observer)).is_err());
/// assert_eq!(copied.borrow().len(), 1);
/// ```
pub struct BorrowContract;
