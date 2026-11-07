//! Actual PROGRAM configuration/options and one explicitly owned runtime task.
use crate::Tool;
use gnunet_client_host::{EndpointSource, LiveConfiguration};
use gnunet_pils::Profile;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Filename, Target},
    logging::Logger,
    program::{self, Defaults, Invocation, NlsDisabled, Preparation, Prepared},
    shared_clock::SharedClock,
};
use gnunet_service_runtime::clock::RuntimeClock;
use std::{
    cell::RefCell,
    error::Error,
    io::{self, Write},
    rc::Rc,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
mod session;
type Failure = Box<dyn Error>;
fn diagnostic(args: std::fmt::Arguments<'_>) {
    let _diagnostic = writeln!(io::stderr().lock(), "{args}");
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Export,
    Import,
    Dump,
    Identity,
}
struct Settings {
    mode: Mode,
    binary: bool,
    expiry: Option<u64>,
    once: bool,
    duration: Duration,
    profile: Profile,
    pils_socket: Option<std::path::PathBuf>,
    peerstore_socket: Option<std::path::PathBuf>,
    slice: usize,
}
fn filename(target: Target<Filename>) -> Result<Option<std::path::PathBuf>, Failure> {
    let result = target.get()?;
    if let Some(error) = result.error {
        return Err(format!("public endpoint filename expansion: {error}").into());
    }
    Ok(result.path)
}
fn selected_profile(
    config: &gnunet_config::Configuration,
    explicit: Option<&[u8]>,
) -> Result<Profile, gnunet_types::Error> {
    // An explicit public endpoint may belong to another node/build profile.
    // Without that override, use the same node choice as its normal services.
    match explicit {
        Some(label) => Profile::from_label(label),
        None => Profile::configured(config.get(b"PILS", b"PROFILE"), None),
    }
}
/// Run the current installed gnunet-hello or gnunet-pils PROGRAM. Crypto/public
/// verification calls in this production source execute only when the user runs
/// the actual program, never during source construction or option parsing.
pub fn run(tool: Tool) -> Result<(), Failure> {
    let result = prepare_and_run(tool);
    let flush = io::stdout().flush().err();
    Failures {
        task: result.err(),
        flush,
        ..Default::default()
    }
    .finish()
}
fn prepare_and_run(tool: Tool) -> Result<(), Failure> {
    let export = Target::new(0i32);
    let import = Target::new(0i32);
    let dump = Target::new(0i32);
    let binary = Target::new(0i32);
    let once = Target::new(0i32);
    let expiry = Target::new(None);
    let duration = Target::new(if tool == Tool::Pils {
        300_000u32
    } else {
        30_000u32
    });
    let profile = Target::new(None);
    let slice = Target::new(65535u32);
    let pils_socket = Target::new(Filename {
        path: None,
        error: None,
    });
    let peerstore_socket = Target::new(Filename {
        path: None,
        error: None,
    });
    let mut options = Options::new();
    match tool {
        Tool::Hello => {
            options.add(helpers::flag(
                b'e',
                b"export-hello",
                b"export current public PILS HELLO",
                export.clone(),
            ));
            options.add(helpers::flag(
                b'i',
                b"import-hello",
                b"import public stdin HELLO via real PEERSTORE hello_add",
                import.clone(),
            ));
            options.add(helpers::flag(
                b'D',
                b"dump-hellos",
                b"list known valid peer HELLOs and public addresses",
                dump.clone(),
            ));
            options.add(helpers::flag(
                b'b',
                b"binary",
                b"export official binary HELLO instead of URL",
                binary.clone(),
            ));
            options.add(helpers::string(
                b'E',
                b"expiration",
                b"TIME",
                b"re-sign exported HELLO through actual PILS purpose7 (relative time)",
                expiry.clone(),
            ));
        }
        Tool::Pils => options.add(helpers::flag(
            b'1',
            b"once",
            b"print one actual public identity observation and exit",
            once.clone(),
        )),
    }
    options.add(helpers::uint(
        0,
        b"duration-ms",
        b"MS",
        b"finite run/operation window; default HELLO30s or PILS5min",
        duration.clone(),
    ));
    options.add(helpers::uint(
        0,
        b"io-slice-bytes",
        b"BYTES",
        b"actual native MQ syscall byte slice",
        slice.clone(),
    ));
    options.add(helpers::string(
        0,
        b"profile",
        b"PROFILE",
        b"override node PILS PROFILE for this public endpoint: reference029 or deterministic",
        profile.clone(),
    ));
    options.add(helpers::filename(
        0,
        b"pils-socket",
        b"PATH",
        b"explicit actual public PILS endpoint",
        pils_socket.clone(),
    ));
    options.add(helpers::filename(
        0,
        b"peerstore-socket",
        b"PATH",
        b"explicit actual PEERSTORE endpoint",
        peerstore_socket.clone(),
    ));
    let config = gnunet_config::Configuration::create(
        Arc::new(gnunet_config::ProjectData::default()),
        Default::default(),
    )?;
    let clock = SharedClock::native(16)?;
    let name: &'static [u8] = if tool == Tool::Hello {
        b"gnunet-hello"
    } else {
        b"gnunet-pils"
    };
    let mut logger = Logger::new(name, std::process::id(), false)?;
    let prepared=program::prepare(config,Invocation{binary_name:name,help:Some(b"Current installed official HELLO/PILS public-peer tools. HELLO -e exports real public announcement; -b binary; -E uses original actual PILS purpose7 result; -i imports URL or binary stdin with scan/newer/REPLACE; -D lists HELLOs to real iterator END. PILS -1 prints one public identity; default finite continuous observation. No private-key path/file, generation, local signer, fake identity or peerinfo protocol."),select_default_filename:true,defaults:Defaults::Native},options,std::env::args_os(),&program::Environment::capture(),&mut NlsDisabled,&mut logger,&clock,&mut io::stdout().lock(),&mut io::stderr().lock())?;
    let prepared = match prepared {
        Preparation::Ready(p) => *p,
        Preparation::Stopped(s) => {
            return if s.code == 0 && matches!(&s.reason, program::StoppedReason::Options) {
                Ok(())
            } else {
                Err(format!("public peer PROGRAM stopped {:?} code={}", s.reason, s.code).into())
            };
        }
    };
    if !prepared.main().arguments.is_empty() {
        return Err("public peer tools accept no positional arguments".into());
    }
    let mode = if tool == Tool::Pils {
        Mode::Identity
    } else {
        match (export.get()? != 0, import.get()? != 0, dump.get()? != 0) {
            (true, false, false) => Mode::Export,
            (false, true, false) => Mode::Import,
            (false, false, true) => Mode::Dump,
            _ => return Err("select exactly one HELLO action: -e, -i or -D".into()),
        }
    };
    let expiry = expiry
        .get()?
        .map(|value| gnunet_config::parse_relative_time(&value))
        .transpose()?;
    if (expiry.is_some() || binary.get()? != 0) && mode != Mode::Export {
        return Err("--binary/--expiration require --export-hello".into());
    }
    let profile = selected_profile(prepared.main().config, profile.get()?.as_deref())?;
    let ms = duration.get()?;
    let slice = slice.get()?;
    if ms == 0 || ms > 86_400_000 || slice == 0 || slice > 65535 {
        return Err("invalid finite public-peer resource/time policy".into());
    }
    let duration = Duration::from_millis(u64::from(ms));
    if Instant::now()
        .checked_add(duration + Duration::from_secs(5))
        .is_none()
    {
        return Err("public peer original deadline overflow".into());
    }
    let settings = Settings {
        mode,
        binary: binary.get()? != 0,
        expiry,
        once: once.get()? != 0,
        duration,
        profile,
        pils_socket: filename(pils_socket)?,
        peerstore_socket: filename(peerstore_socket)?,
        slice: slice as usize,
    };
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(scheduled(prepared, clock, settings))
}
#[derive(Debug, Default)]
struct Failures {
    program: Option<Failure>,
    task: Option<Failure>,
    client: Option<Failure>,
    resolver: Option<Failure>,
    flush: Option<io::Error>,
}
impl std::fmt::Display for Failures {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "public peer program failures program={:?} task={:?} client-cleanup={:?} resolver-cleanup={:?} independent-stdio-flush={:?}",
            self.program, self.task, self.client, self.resolver, self.flush
        )
    }
}
impl Error for Failures {}
impl Failures {
    fn finish(self) -> Result<(), Failure> {
        if self.program.is_none()
            && self.task.is_none()
            && self.client.is_none()
            && self.resolver.is_none()
            && self.flush.is_none()
        {
            Ok(())
        } else {
            Err(Box::new(self))
        }
    }
}
async fn scheduled(
    prepared: Prepared,
    clock: SharedClock,
    settings: Settings,
) -> Result<(), Failure> {
    let config = prepared.main().config.duplicate()?;
    let runtime_clock: Arc<dyn RuntimeClock> = Arc::new(clock.clone());
    let live = LiveConfiguration::new(config);
    let (mut context, resolver) = gnunet_resolver_broker::broker::<8, 256>(
        live.clone(),
        Default::default(),
        gnunet_resolver_broker::native_profile()?,
        runtime_clock.clone(),
    )?;
    let source = match settings.mode {
        Mode::Export | Mode::Identity => settings
            .pils_socket
            .clone()
            .map(|path| EndpointSource::unix_with_clock(path, runtime_clock.clone()))
            .unwrap_or_else(|| EndpointSource::live(live, b"pils", context.resolution_context())),
        Mode::Import | Mode::Dump => settings
            .peerstore_socket
            .clone()
            .map(|path| EndpointSource::unix_with_clock(path, runtime_clock.clone()))
            .unwrap_or_else(|| {
                EndpointSource::live(live, b"peerstore", context.resolution_context())
            }),
    };
    let result = Rc::new(RefCell::new(None));
    let receiving = Rc::clone(&result);
    let program = prepared
        .run_scheduled(&mut context, clock, 1, move |_main, scope| {
            let destination = Rc::clone(&receiving);
            let stopping = scope.clone();
            if let Err(error) = scope.spawn(async move {
                *destination.borrow_mut() =
                    Some(session::run(source, resolver, runtime_clock, settings).await);
                if let Err(error) = stopping.shutdown() {
                    let previous = destination.borrow_mut().take().and_then(Result::err);
                    *destination.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(error)),
                            task: previous,
                            ..Default::default()
                        }
                        .finish(),
                    );
                }
            }) {
                *receiving.borrow_mut() = Some(Err(Box::new(error) as Failure));
                if let Err(error) = scope.shutdown() {
                    let previous = receiving.borrow_mut().take().and_then(Result::err);
                    *receiving.borrow_mut() = Some(
                        Failures {
                            program: Some(Box::new(error)),
                            task: previous,
                            ..Default::default()
                        }
                        .finish(),
                    );
                }
            }
        })
        .await;
    let task = result
        .borrow_mut()
        .take()
        .unwrap_or_else(|| Err("PROGRAM ended without public peer task result".into()))
        .err();
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(format!("PROGRAM returned source code{code}").into()),
        Err(error) => Some(Box::new(error) as Failure),
    };
    Failures {
        program,
        task,
        ..Default::default()
    }
    .finish()
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Compare the public endpoint profile selection contract"
    )]
    fn node_choice_is_inherited_unless_endpoint_profile_is_explicit() -> Result<(), Failure> {
        let mut config = gnunet_config::Configuration::default();
        assert_eq!(selected_profile(&config, None)?, Profile::Reference029);
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            selected_profile(&config, None)?,
            Profile::ReferenceDeterministic
        );
        assert_eq!(
            selected_profile(&config, Some(b"reference-0.29.1"))?,
            Profile::Reference029
        );
        assert_eq!(
            selected_profile(&config, Some(b"unrecognized")),
            Err(gnunet_types::Error::InvalidInput)
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"unrecognized"))?;
        assert_eq!(
            selected_profile(&config, None),
            Err(gnunet_types::Error::InvalidInput)
        );
        assert_eq!(
            selected_profile(&config, Some(b"deterministic"))?,
            Profile::ReferenceDeterministic
        );
        Ok(())
    }
}
