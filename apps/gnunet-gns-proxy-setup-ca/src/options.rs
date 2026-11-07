//! Official helper options, including distinct -v version and -V verbosity.
use crate::Cause;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};

pub(super) struct Selection {
    verbose: Target<i32>,
    probe: Target<i32>,
    summary: Target<i32>,
}
pub(super) struct Chosen {
    pub verbose: bool,
    pub probe: bool,
    pub summary: bool,
}
impl Selection {
    pub(super) fn new() -> Self {
        Self {
            verbose: Target::new(0),
            probe: Target::new(0),
            summary: Target::new(0),
        }
    }
    pub(super) fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::flag(
            b'V',
            b"verbose",
            b"Print preparation details; -v prints the version",
            self.verbose.clone(),
        ));
        options.add(helpers::flag(b't', b"test", b"Report compiled CA provider and probe the optional NSS helper without installing a CA", self.probe.clone()));
        options.add(helpers::flag(
            b'o',
            b"output",
            b"Repeat the bounded status summary after preparation",
            self.summary.clone(),
        ));
        options
    }
    pub(super) fn finish(self, arguments: &[Vec<u8>]) -> Result<Chosen, Cause> {
        if !arguments.is_empty() {
            return Err("gnunet-gns-proxy-setup-ca accepts no positional arguments".into());
        }
        Ok(Chosen {
            verbose: self.verbose.get()? != 0,
            probe: self.probe.get()? != 0,
            summary: self.summary.get()? != 0,
        })
    }
}
