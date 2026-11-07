//! Synchronous CONFIG-to-PROGRAM logging composition. The callback borrow never
//! enters Configuration, crosses a thread or survives the selected operation.
use crate::{
    format::{self, Argument as Value},
    logging::{Logger, Stamp},
    policy::{CallSite, Level},
    shared_clock::SharedClock,
};
use gnunet_config::diagnostic::{Argument, BorrowedObserver, Diagnostic};
use std::{
    cell::RefCell,
    io::{self, Write},
};
enum Owned {
    Bytes(Vec<u8>),
    Signed(i64),
    Unsigned(u64),
}
fn render(
    event: Diagnostic<'_>,
    translations: &dyn crate::locale::Translations,
) -> io::Result<Vec<u8>> {
    let mut owned = Vec::with_capacity(event.arguments.len());
    for argument in event.arguments {
        owned.push(match argument {
            Argument::Bytes(value) => Owned::Bytes(value.to_vec()),
            Argument::Signed(value) => Owned::Signed(*value),
            Argument::Unsigned(value) => Owned::Unsigned(*value),
            Argument::Error(error) => Owned::Bytes(crate::native::strerror(
                error.raw_os_error().ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::Unsupported,
                        "configuration error has no native errno",
                    )
                })?,
            )),
            Argument::Translated { domain, message } => {
                Owned::Bytes(translations.gettext(Some(domain), message)?)
            }
            // Explicit safe Rust correction. Undefined C NULL/%s inputs are never run by
            // reference tools and receive no normal-C equivalence credit.
            Argument::NullString => Owned::Bytes(b"(null)".to_vec()),
        });
    }
    let args = owned
        .iter()
        .map(|v| match v {
            Owned::Bytes(v) => Value::Bytes(v),
            Owned::Signed(v) => Value::Signed(*v),
            Owned::Unsigned(v) => Value::Unsigned(*v),
        })
        .collect::<Vec<_>>();
    let template = if let Some(domain) = event.domain {
        translations.gettext(Some(domain), event.template)?
    } else {
        event.template.to_vec()
    };
    format::render(&template, &args)
}
/// Immediately route one original configuration callsite through actual logger
/// policy, source cache, debug profile, skip, NLS, clock and destination owners.
/// Formatting/errno/translation is evaluated only after log admission.
pub fn log(
    logger: &mut Logger<'_>,
    clock: &SharedClock,
    stderr: &mut impl Write,
    event: Diagnostic<'_>,
) -> io::Result<()> {
    let translations = logger.translations();
    logger.source_lazy(
        event.site.id,
        Level(event.level.0),
        CallSite {
            component: event.component,
            file: event.site.file,
            function: event.site.function,
            line: i32::try_from(event.site.line)
                .map_err(|_| io::Error::other("configuration source line overflow"))?,
        },
        || render(event, translations.as_ref()),
        || Stamp::now(clock.offset().map_err(io::Error::other)?),
        stderr,
    )
}
/// Execute one real configuration operation with immediate logging. A local
/// observer replaces persistent observation along the entire nested parse path.
/// The first actual logger/NLS/output error is returned distinctly from CONFIG's
/// result. The parser still follows its own source result and progress rules.
/// No diagnostics are reconstructed from a collapsed final configuration error.
pub fn operation<T, E>(
    logger: &mut Logger<'_>,
    clock: &SharedClock,
    stderr: &mut impl Write,
    operation: impl FnOnce(BorrowedObserver<'_>) -> Result<T, E>,
) -> io::Result<Result<T, E>> {
    let route = Route::new(logger, clock, stderr);
    let observer = |event: Diagnostic<'_>| route.event(event);
    let result = operation(&observer);
    route.finish()?;
    Ok(result)
}
/// Borrowed single logging route for synchronous operations and caller-polled
/// futures. The owner stores no RefCell guard across await and creates no task.
/// Native logger/locale handles remain alive through the original exclusive
/// borrow. A recursive attempt at this same route is an explicit failure.
pub struct Route<'route, 'log, W> {
    state: RefCell<(&'route mut Logger<'log>, &'route mut W)>,
    clock: &'route SharedClock,
    failure: RefCell<Option<io::Error>>,
}
impl<'route, 'log, W: Write> Route<'route, 'log, W> {
    /// Borrow one actual logger/clock/output set; no callback or IO occurs here.
    pub fn new(
        logger: &'route mut Logger<'log>,
        clock: &'route SharedClock,
        stderr: &'route mut W,
    ) -> Self {
        Self {
            state: RefCell::new((logger, stderr)),
            clock,
            failure: RefCell::new(None),
        }
    }
    /// Route a borrowed source event immediately. The first actual IO/NLS or
    /// reentrant-route failure is retained until finish, never English success.
    pub fn event(&self, event: Diagnostic<'_>) {
        if self.failure.borrow().is_some() {
            return;
        }
        let result = self.with_logger(|logger, clock, stderr| log(logger, clock, stderr, event));
        if let Err(error) = result {
            *self.failure.borrow_mut() = Some(error);
        }
    }
    /// Run synchronous application logging/configuration at a callback read
    /// point while retaining the same route. Returned data must own its bytes;
    /// no logger/writer borrow can escape the operation.
    pub fn with_logger<T>(
        &self,
        operation: impl FnOnce(&mut Logger<'log>, &SharedClock, &mut W) -> io::Result<T>,
    ) -> io::Result<T> {
        let mut pair = self
            .state
            .try_borrow_mut()
            .map_err(|_| io::Error::other("logging route is already active"))?;
        let (logger, stderr) = &mut *pair;
        operation(logger, self.clock, stderr)
    }
    /// Release the original logger/writer borrows and return the first failure.
    pub fn finish(self) -> io::Result<()> {
        match self.failure.into_inner() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
