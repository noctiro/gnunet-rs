//! One caller-selected PROGRAM locale shared by parsing, configuration and output.
use gnunet_config::{CaseContext, ProjectData};
use gnunet_program_host::{
    format::{self, Argument},
    locale::Translations,
    program::{Failure, LocaleSetup},
};
use std::{fmt, io, rc::Rc};

/// Retained translation and case capabilities from one explicit locale setup.
/// Clones share the original backend; no native library is discovered or loaded.
#[derive(Clone)]
pub struct Locale {
    translations: Rc<dyn Translations>,
    cases: Option<CaseContext>,
}
impl fmt::Debug for Locale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Locale").finish_non_exhaustive()
    }
}
impl Locale {
    /// Explicit ENABLE_NLS=0 profile, without a native locale transition.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            translations: gnunet_program_host::locale::disabled(),
            cases: None,
        }
    }
    /// Configure the supplied PROGRAM locale before parsing or native owners.
    /// Enabled backend failures return unchanged; they never select disabled NLS.
    ///
    /// # Errors
    /// Preserves the original locale/catalog installation failure.
    pub fn configure(setup: &mut impl LocaleSetup, project: &ProjectData) -> Result<Self, Failure> {
        setup.configure(project)?;
        Ok(Self {
            translations: setup.translations(),
            cases: setup.case_context(),
        })
    }
    /// The same replaceable comparison context used by configuration and Logger.
    #[must_use]
    pub fn case_context(&self) -> Option<CaseContext> {
        self.cases.clone()
    }
    pub(crate) fn port(&self) -> Rc<dyn Translations> {
        Rc::clone(&self.translations)
    }
    pub(crate) fn text(&self, message: &[u8]) -> io::Result<Vec<u8>> {
        self.translations.gettext(Some(b"gnunet"), message)
    }
    pub(crate) fn format(&self, message: &[u8], args: &[Argument<'_>]) -> io::Result<Vec<u8>> {
        format::render(&self.text(message)?, args)
    }
}
