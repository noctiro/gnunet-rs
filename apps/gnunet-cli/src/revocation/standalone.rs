//! Official options, configured service endpoints and certificate operations.
mod proof_file;
mod work;

use super::{Certificate, Result, ZoneKey, identity, native, observe, pure, until};
use gnunet_config::Configuration;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Filename, Target},
};
use gnunet_service_runtime::signals::Termination;
use proof_file::ProofFile;
use std::{
    future::poll_fn,
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};
use tokio::time::Instant;

const COMMAND: &[u8] = b"gnunet-revocation";
const TIMEOUT: Duration = Duration::from_secs(30);

struct Arguments {
    filename: Target<Filename>,
    ego: Target<Option<Vec<u8>>>,
    perform: Target<i32>,
    query: Target<Option<Vec<u8>>>,
    epochs: Target<u32>,
}

enum Operation {
    None,
    Query {
        text: String,
        key: ZoneKey,
    },
    Certificate {
        ego: Option<Vec<u8>>,
        filename: Option<PathBuf>,
        perform: bool,
        work: work::Policy,
    },
}

impl Arguments {
    fn new() -> Self {
        Self {
            filename: Target::new(Filename {
                path: None,
                error: None,
            }),
            ego: Target::new(None),
            perform: Target::new(0),
            query: Target::new(None),
            epochs: Target::new(1),
        }
    }

    fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::filename(
            b'f',
            b"filename",
            b"NAME",
            b"Read or store the revocation certificate in NAME",
            self.filename.clone(),
        ));
        options.add(helpers::string(
            b'R',
            b"revoke",
            b"NAME",
            b"Select the ego to revoke",
            self.ego.clone(),
        ));
        options.add(helpers::flag(
            b'p',
            b"perform",
            b"Submit the revocation after preparing the certificate",
            self.perform.clone(),
        ));
        options.add(helpers::string(
            b't',
            b"test",
            b"KEY",
            b"Test if the public key KEY has been revoked",
            self.query.clone(),
        ));
        options.add(helpers::uint(
            b'e',
            b"epochs",
            b"EPOCHS",
            b"Set the number of epochs for proof calculation",
            self.epochs.clone(),
        ));
        options
    }

    fn operation(&self, config: &Configuration) -> Result<Operation> {
        let ego = self.ego.get()?;
        if let Some(query) = self.query.get()? {
            let text = String::from_utf8(query)?;
            let key =
                ZoneKey::from_ztld(&text).map_err(|_| format!("Public key `{text}' malformed"))?;
            if ego.is_some() {
                writeln!(
                    io::stderr().lock(),
                    "Testing and revoking at the same time is not allowed, only executing test."
                )?;
            }
            return Ok(Operation::Query { text, key });
        }
        let Filename {
            path: filename,
            error,
        } = self.filename.get()?;
        if let Some(error) = error {
            return Err(error.to_string().into());
        }
        let perform = self.perform.get()? != 0;
        if ego.is_none() && (filename.is_none() || !perform) {
            return Ok(Operation::None);
        }
        if ego.is_some() && !perform && filename.is_none() {
            return Err("No filename to store revocation certificate given.".into());
        }
        if let Some(name) = &ego
            && (name.is_empty()
                || name.contains(&0)
                || name.len() > identity::Limits::default().name_bytes)
        {
            return Err("invalid IDENTITY ego name".into());
        }
        let work = work::Policy::read(config, self.epochs.get()?)?;
        Ok(Operation::Certificate {
            ego,
            filename,
            perform,
            work,
        })
    }
}

pub(crate) fn run() -> Result<()> {
    let arguments = Arguments::new();
    let Some((prepared, clock)) = crate::configured::prepare(
        COMMAND,
        b"Query a public key or prepare and submit a GNUnet revocation certificate.",
        arguments.options(),
    )?
    else {
        return Ok(());
    };
    let main = prepared.main();
    if !main.arguments.is_empty() {
        return Err("unexpected positional revocation arguments".into());
    }
    match arguments.operation(main.config)? {
        Operation::None => {
            writeln!(io::stderr().lock(), "No action specified. Nothing to do.")?;
            Ok(())
        }
        Operation::Query { text, key } => crate::configured::run(
            main.config,
            clock,
            [b"revocation"],
            move |[revocation]| async move {
                let mut signals = Termination::new()?;
                exchange(
                    revocation,
                    Request::Query { key, text: &text },
                    &mut signals,
                )
                .await
            },
        ),
        Operation::Certificate {
            ego,
            filename,
            perform,
            work,
        } => crate::configured::run(
            main.config,
            clock,
            [b"identity", b"revocation"],
            move |[identity, revocation]| async move {
                certificate(
                    ego.as_deref(),
                    filename,
                    perform,
                    work,
                    identity,
                    revocation,
                )
                .await
            },
        ),
    }
}

async fn certificate(
    ego: Option<&[u8]>,
    filename: Option<PathBuf>,
    perform: bool,
    policy: work::Policy,
    identity: native::EndpointSource,
    revocation: native::EndpointSource,
) -> Result<()> {
    let mut signals = Termination::new()?;
    let clock = revocation.clock();
    let (file, saved) = match filename {
        Some(path) => {
            let (file, saved) =
                ProofFile::read(path).map_err(|error| error as Box<dyn std::error::Error>)?;
            (Some(file), saved)
        }
        None => (None, None),
    };
    let existing = saved.is_some();
    let seed = match ego {
        Some(name) => {
            let Some(identity) = lookup(identity, name, &mut signals).await? else {
                writeln!(
                    io::stdout().lock(),
                    "Ego `{}' not found.",
                    String::from_utf8_lossy(name)
                )?;
                return Ok(());
            };
            let public = ZoneKey::from_wire(&identity.public_key()?)?;
            if let Some(saved) = saved {
                if saved.proof()?.public()? != public {
                    return Err(format!(
                        "revocation certificate is not for `{}`",
                        String::from_utf8_lossy(name)
                    )
                    .into());
                }
                saved
            } else {
                let now = clock.sample()?.now.as_micros();
                super::sign_template(
                    &identity,
                    public,
                    now.saturating_sub(pure::PREDATE_MICROS),
                    policy.ttl(),
                )?
            }
        }
        None => saved.ok_or("revocation certificate file does not exist")?,
    };
    let path = file.as_ref().map(|file| file.path().to_owned());
    let result = work::prepare(seed, existing, file, policy, clock, &mut signals).await?;
    if result.already_ready {
        writeln!(io::stderr().lock(), "Revocation certificate ready")?;
    }
    if perform {
        exchange(
            revocation,
            Request::Revoke {
                proof: &result.certificate,
                ego,
            },
            &mut signals,
        )
        .await
    } else {
        if let (false, Some(ego), Some(path)) = (result.already_ready, ego, path) {
            writeln!(
                io::stderr().lock(),
                "Revocation certificate for `{}' stored in `{}'",
                String::from_utf8_lossy(ego),
                path.display()
            )?;
        }
        Ok(())
    }
}

async fn lookup(
    source: native::EndpointSource,
    name: &[u8],
    signals: &mut Termination,
) -> Result<Option<identity::Identity>> {
    let domain = identity::Instance::new();
    let deadline = until(source.clock().as_ref(), TIMEOUT)?;
    let hard = Instant::now()
        .checked_add(TIMEOUT)
        .ok_or("IDENTITY deadline overflow")?;
    let mut lookup = identity::Lookup::exact(
        &domain,
        source,
        name,
        deadline,
        identity::Limits {
            reconnect: false,
            ..Default::default()
        },
    )?;
    let mut stop = std::pin::pin!(poll_fn(|cx| signals.poll_stop(cx)));
    let result = async {
        loop {
            match observe(lookup.drive(Some(hard)), stop.as_mut()).await? {
                Some(identity::LookupProgress::Finished {
                    outcome: identity::LookupOutcome::Found(ego),
                    ..
                }) => return Ok(Some(ego)),
                Some(identity::LookupProgress::Finished {
                    outcome: identity::LookupOutcome::ResultCode(200),
                    ..
                }) => return Ok(None),
                Some(identity::LookupProgress::Finished { outcome, .. }) => {
                    return Err(format!("original IDENTITY lookup failed: {outcome:?}").into());
                }
                Some(
                    identity::LookupProgress::Closed
                    | identity::LookupProgress::Source(identity::Progress::WaitDeadline),
                ) => return Err("original IDENTITY lookup ended".into()),
                Some(identity::LookupProgress::Source(_)) => {}
                None => return Err("revocation interrupted while looking up the named ego".into()),
            }
        }
    }
    .await;
    let _closed = lookup.close();
    result
}

enum Request<'a> {
    Query {
        key: ZoneKey,
        text: &'a str,
    },
    Revoke {
        proof: &'a Certificate,
        ego: Option<&'a [u8]>,
    },
}

async fn exchange(
    source: native::EndpointSource,
    request: Request<'_>,
    signals: &mut Termination,
) -> Result<()> {
    let deadline = until(source.clock().as_ref(), TIMEOUT)?;
    let hard = Instant::now()
        .checked_add(TIMEOUT)
        .ok_or("REVOCATION deadline overflow")?;
    let deadlines = native::Deadlines {
        send_until: deadline,
        until: deadline,
    };
    let domain = native::Instance::new();
    let mut client = match &request {
        Request::Query { key, .. } => {
            native::Client::query(&domain, source, *key, deadlines, Default::default())?
        }
        Request::Revoke { proof, .. } => native::Client::revoke(
            &domain,
            source,
            proof.proof()?,
            deadlines,
            Default::default(),
        )?,
    };
    let mut stop = std::pin::pin!(poll_fn(|cx| signals.poll_stop(cx)));
    let result = async {
        loop {
            match observe(client.drive(Some(hard)), stop.as_mut()).await? {
                Some(native::Progress::Reply(reply)) if reply.job == client.job() && Some(reply.epoch) == client.epoch() => return report(request, reply.response),
                Some(native::Progress::Reply(_)) => return Err("REVOCATION response came from a different original source".into()),
                Some(native::Progress::Ended(end)) => return Err(format!("original REVOCATION request ended: {:?}, exposure {:?}", end.cause, end.submission).into()),
                Some(native::Progress::Unavailable(error)) => return Err(error.into()),
                Some(native::Progress::WaitDeadline) => {
                    let ended = client.close();
                    return Err(format!("original REVOCATION response deadline elapsed, request exposure {:?}", ended.map(|end| end.submission)).into());
                }
                Some(native::Progress::Closed) => return Err("original REVOCATION request ended without a response".into()),
                Some(_) => {},
                None => {
                    let ended = client.cancel();
                    return Err(format!("REVOCATION interrupted before the original response, request exposure {:?}", ended.map(|end| end.submission)).into());
                }
            }
        }
    }.await;
    let _closed = client.close();
    result
}

fn report(request: Request<'_>, reply: pure::ipc::Response) -> Result<()> {
    let mut out = io::stdout().lock();
    match (request, reply) {
        (Request::Query { text, .. }, pure::ipc::Response::Query(1)) => {
            writeln!(out, "Key `{text}' is valid")?
        }
        (Request::Query { text, .. }, pure::ipc::Response::Query(0)) => {
            writeln!(out, "Key `{text}' has been revoked")?
        }
        (Request::Query { .. }, pure::ipc::Response::Query(u32::MAX)) => {
            writeln!(out, "Internal error")?
        }
        (Request::Revoke { ego: Some(ego), .. }, pure::ipc::Response::Revoke(0)) => writeln!(
            out,
            "Key for ego `{}' has been successfully revoked",
            String::from_utf8_lossy(ego)
        )?,
        (Request::Revoke { ego: Some(ego), .. }, pure::ipc::Response::Revoke(1)) => writeln!(
            out,
            "Key for ego `{}' is still valid, revocation failed (!)",
            String::from_utf8_lossy(ego)
        )?,
        (Request::Revoke { .. }, pure::ipc::Response::Revoke(0)) => {
            writeln!(out, "Revocation successful.")?
        }
        (Request::Revoke { .. }, pure::ipc::Response::Revoke(1)) => {
            writeln!(out, "Revocation failed (!)")?
        }
        (Request::Revoke { .. }, pure::ipc::Response::Revoke(u32::MAX)) => {
            writeln!(out, "Internal error, key revocation might have failed")?
        }
        _ => return Err(format!("unexpected REVOCATION response {reply:?}").into()),
    }
    out.flush()?;
    Ok(())
}
