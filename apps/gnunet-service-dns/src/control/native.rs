//! One explicit management transaction driven on the application's main thread.
use super::arguments::{Command, Options};
use crate::{Failure, settings::Settings};
use gnunet_native::dns_proxy::{
    application::{Application, Identity},
    extension::{self, Finished, ReplacementPolicy},
    management::{Configuration, Manager, Mode, Operation},
};
use std::{
    io::{self, Write},
    task::{Context, Poll, Waker},
    time::Instant,
};

pub(super) fn run(options: Options) -> Result<(), Failure> {
    let identity = Application::identity()?;
    let mut driver = Driver::new(options, identity)?;
    Application::run(move || driver.poll())?
}

enum Intent {
    Status,
    Enable(Configuration),
    Disable,
    Remove,
}
enum Phase {
    Begin(Command),
    Activating {
        original: extension::Operation,
        configuration: Configuration,
    },
    Loading {
        original: Manager,
        intent: Intent,
    },
    Saving {
        original: Manager,
        operation: Operation,
        expected: Expected,
    },
    Verifying {
        original: Manager,
        expected: Expected,
    },
    Removing(Manager),
    Deactivating(extension::Operation),
    Done,
}
impl Phase {
    fn name(&self) -> &'static str {
        match self {
            Self::Begin(_) => "admission",
            Self::Activating { .. } => "extension activation",
            Self::Loading { .. } => "preferences load",
            Self::Saving { .. } => "preferences save",
            Self::Verifying { .. } => "saved preferences reload",
            Self::Removing(_) => "preferences removal",
            Self::Deactivating(_) => "extension deactivation",
            Self::Done => "completed operation",
        }
    }
}
struct Driver {
    identity: Identity,
    until: Instant,
    phase: Phase,
}
enum Step {
    Pending(Phase),
    Next(Phase),
    Complete,
}
enum Expected {
    Enabled(std::path::PathBuf),
    Disabled,
}
impl Driver {
    fn new(options: Options, identity: Identity) -> Result<Self, Failure> {
        // Validate the same explicit bundle defaults and shared service policy
        // before submitting an activation or preference mutation. This check
        // grants neither provider filesystem access nor listener readiness.
        if let Command::Enable { configuration, .. } = &options.command {
            let contents = identity
                .bundle_path
                .join("Contents/Library/SystemExtensions")
                .join(format!("{}.systemextension", identity.provider_identifier))
                .join("Contents");
            let config = crate::provider::configuration::load(
                configuration,
                &contents.join("Resources"),
                &contents.join("MacOS"),
            )?;
            Settings::read_provider(&config)?.statistics.validate()?;
        }
        Ok(Self {
            identity,
            until: Instant::now()
                .checked_add(options.timeout)
                .ok_or("command deadline overflow")?,
            phase: Phase::Begin(options.command),
        })
    }
    fn poll(&mut self) -> Poll<Result<(), Failure>> {
        for _ in 0..4 {
            if Instant::now() >= self.until {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("{} wait expired; any submitted native effect remains unconfirmed and was not canceled", self.phase.name()),
                ).into()));
            }
            let phase = std::mem::replace(&mut self.phase, Phase::Done);
            match self.step(phase) {
                Ok(Step::Pending(phase)) => {
                    self.phase = phase;
                    return Poll::Pending;
                }
                Ok(Step::Next(phase)) => self.phase = phase,
                Ok(Step::Complete) => return Poll::Ready(Ok(())),
                Err(error) => return Poll::Ready(Err(error)),
            }
        }
        Poll::Pending
    }
    fn load(&self, intent: Intent) -> Result<Phase, Failure> {
        let mut original = Manager::new(&self.identity.provider_identifier)?;
        original.begin_load()?;
        Ok(Phase::Loading { original, intent })
    }
    fn step(&self, phase: Phase) -> Result<Step, Failure> {
        let mut cx = Context::from_waker(Waker::noop());
        match phase {
            Phase::Begin(command) => Ok(Step::Next(match command {
                Command::Status => self.load(Intent::Status)?,
                Command::Disable => self.load(Intent::Disable)?,
                Command::Remove => self.load(Intent::Remove)?,
                Command::Enable {
                    configuration,
                    replace,
                } => {
                    let configuration =
                        Configuration::new(&self.identity.provider_identifier, &configuration)?;
                    let policy = if replace {
                        ReplacementPolicy::UpgradeTo(self.identity.provider_version.parse()?)
                    } else {
                        ReplacementPolicy::Reject
                    };
                    Phase::Activating {
                        original: extension::Operation::activate(
                            &self.identity.provider_identifier,
                            policy,
                        )?,
                        configuration,
                    }
                }
            })),
            Phase::Activating {
                mut original,
                configuration,
            } => match extension_result(&mut original, &mut cx)? {
                Some(Finished::Completed) => {
                    Ok(Step::Next(self.load(Intent::Enable(configuration))?))
                }
                Some(Finished::AfterReboot) => Err(
                    "extension activation requires a restart; no DNS preference save was submitted"
                        .into(),
                ),
                None => Ok(Step::Pending(Phase::Activating {
                    original,
                    configuration,
                })),
            },
            Phase::Loading {
                mut original,
                intent,
            } => {
                if !completed(&mut original, &mut cx, Operation::Load)? {
                    return Ok(Step::Pending(Phase::Loading { original, intent }));
                }
                match intent {
                    Intent::Status => {
                        show(&original)?;
                        Ok(Step::Complete)
                    }
                    Intent::Enable(configuration) => {
                        let expected =
                            Expected::Enabled(configuration.configuration_file().to_owned());
                        original.begin_apply(&configuration, Mode::Enabled)?;
                        Ok(Step::Next(Phase::Saving {
                            original,
                            operation: Operation::Apply,
                            expected,
                        }))
                    }
                    Intent::Disable => {
                        original.begin_disable()?;
                        Ok(Step::Next(Phase::Saving {
                            original,
                            operation: Operation::Disable,
                            expected: Expected::Disabled,
                        }))
                    }
                    Intent::Remove => {
                        if !original.snapshot()?.has_configuration() {
                            return Ok(Step::Next(Phase::Deactivating(
                                extension::Operation::deactivate(
                                    &self.identity.provider_identifier,
                                )?,
                            )));
                        }
                        original.begin_remove()?;
                        Ok(Step::Next(Phase::Removing(original)))
                    }
                }
            }
            Phase::Saving {
                mut original,
                operation,
                expected,
            } => {
                if !completed(&mut original, &mut cx, operation)? {
                    return Ok(Step::Pending(Phase::Saving {
                        original,
                        operation,
                        expected,
                    }));
                }
                original.begin_load()?;
                Ok(Step::Next(Phase::Verifying { original, expected }))
            }
            Phase::Verifying {
                mut original,
                expected,
            } => {
                if !completed(&mut original, &mut cx, Operation::Load)? {
                    return Ok(Step::Pending(Phase::Verifying { original, expected }));
                }
                show(&original)?;
                let saved = original.snapshot()?;
                let matches = saved.has_configuration()
                    && saved.provider_bundle_identifier()
                        == Some(self.identity.provider_identifier.as_str())
                    && match expected {
                        Expected::Enabled(path) => {
                            saved.enabled()
                                && saved.configuration_error().is_none()
                                && saved.configuration_file() == Some(path.as_path())
                        }
                        Expected::Disabled => !saved.enabled(),
                    };
                if !matches {
                    return Err(
                        "reloaded DNS preferences differ from the requested saved state".into(),
                    );
                }
                Ok(Step::Complete)
            }
            Phase::Removing(mut original) => {
                if !completed(&mut original, &mut cx, Operation::Remove)? {
                    return Ok(Step::Pending(Phase::Removing(original)));
                }
                message("DNS preferences removed; submitting bundled extension deactivation")?;
                Ok(Step::Next(Phase::Deactivating(
                    extension::Operation::deactivate(&self.identity.provider_identifier)?,
                )))
            }
            Phase::Deactivating(mut original) => match extension_result(&mut original, &mut cx)? {
                Some(Finished::Completed) => {
                    message("Extension deactivation request completed")?;
                    Ok(Step::Complete)
                }
                Some(Finished::AfterReboot) => Err(
                    "DNS preferences are absent; extension deactivation still requires a restart"
                        .into(),
                ),
                None => Ok(Step::Pending(Phase::Deactivating(original))),
            },
            Phase::Done => Err("DNS control transaction was already consumed".into()),
        }
    }
}
fn completed(
    manager: &mut Manager,
    cx: &mut Context<'_>,
    expected: Operation,
) -> Result<bool, Failure> {
    match manager.poll_completion(cx) {
        Poll::Pending => Ok(false),
        Poll::Ready(Some(result)) if result.as_ref().is_ok_and(|actual| *actual == expected) => {
            Ok(true)
        }
        Poll::Ready(Some(Err(error))) => Err(error.into()),
        Poll::Ready(_) => Err("original DNS preference completion is missing or mismatched".into()),
    }
}
fn extension_result(
    original: &mut extension::Operation,
    cx: &mut Context<'_>,
) -> Result<Option<Finished>, Failure> {
    for _ in 0..4 {
        match original.poll_event(cx) {
            Poll::Pending => return Ok(None),
            Poll::Ready(Some(extension::Event::Finished(result))) => return Ok(Some(result)),
            Poll::Ready(Some(extension::Event::Failed(error))) => return Err(error.into()),
            Poll::Ready(Some(extension::Event::ApprovalRequired)) => {
                message("System extension is waiting for user approval in macOS System Settings")?
            }
            Poll::Ready(Some(extension::Event::Replacement(observation))) => message(&format!(
                "Extension replacement decision: {:?}",
                observation.decision
            ))?,
            Poll::Ready(None) => {
                return Err("original extension request ended without a final result".into());
            }
        }
    }
    Ok(None)
}
fn show(manager: &Manager) -> Result<(), Failure> {
    let saved = manager.snapshot()?;
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "configuration-present={} saved-enabled={}",
        saved.has_configuration(),
        saved.enabled()
    )?;
    if let Some(identifier) = saved.provider_bundle_identifier() {
        writeln!(out, "provider={identifier}")?;
    }
    if let Some(filename) = saved.configuration_file() {
        writeln!(out, "configuration={}", filename.display())?;
    }
    if let Some(error) = saved.configuration_error() {
        writeln!(out, "configuration-error={error}")?;
    }
    writeln!(
        out,
        "Provider readiness and DNS delivery require an independent service check"
    )?;
    out.flush()?;
    Ok(())
}
fn message(text: &str) -> io::Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{text}")?;
    out.flush()
}
