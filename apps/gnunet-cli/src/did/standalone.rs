//! Configured DID PROGRAM with official action flags and text output.
use super::{OsEntropy, Result, did_text, host};
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use std::{
    io::{self, Write},
    time::Duration,
};
use zeroize::Zeroizing;

const TIMEOUT: Duration = Duration::from_secs(30);

struct Arguments {
    create: Target<i32>,
    get: Target<i32>,
    remove: Target<i32>,
    replace: Target<i32>,
    show: Target<i32>,
    show_all: Target<i32>,
    did: Target<Option<Vec<u8>>>,
    document: Target<Option<Vec<u8>>>,
    ego: Target<Option<Vec<u8>>>,
    expiration: Target<Option<Vec<u8>>>,
}

enum Listing {
    None,
    All,
    Prefix(Vec<u8>),
}

enum Action {
    None,
    Resolve(host::did::Did),
    Remove(Vec<u8>),
    Publish {
        ego: Vec<u8>,
        document: Option<Zeroizing<Vec<u8>>>,
        expiration: u64,
        mode: host::PublishMode,
    },
}

impl Arguments {
    fn new() -> Self {
        Self {
            create: Target::new(0),
            get: Target::new(0),
            remove: Target::new(0),
            replace: Target::new(0),
            show: Target::new(0),
            show_all: Target::new(0),
            did: Target::new(None),
            document: Target::new(None),
            ego: Target::new(None),
            expiration: Target::new(None),
        }
    }

    fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        for (short, name, description, target) in [
            (
                b'C',
                b"create".as_slice(),
                b"Create a DID Document and display its DID".as_slice(),
                &self.create,
            ),
            (
                b'g',
                b"get".as_slice(),
                b"Get the DID Document associated with the given DID".as_slice(),
                &self.get,
            ),
            (
                b'r',
                b"remove".as_slice(),
                b"Remove the DID".as_slice(),
                &self.remove,
            ),
            (
                b'R',
                b"replace".as_slice(),
                b"Replace the DID Document.".as_slice(),
                &self.replace,
            ),
            (
                b's',
                b"show".as_slice(),
                b"Show the DID for a given ego".as_slice(),
                &self.show,
            ),
            (
                b'A',
                b"show-all".as_slice(),
                b"Show egos with DIDs".as_slice(),
                &self.show_all,
            ),
        ] {
            options.add(helpers::flag(short, name, description, target.clone()));
        }
        options.add(helpers::string(
            b'd',
            b"did",
            b"DID",
            b"The Decentralized Identity (DID)",
            self.did.clone(),
        ));
        options.add(helpers::string(
            b'D',
            b"did-document",
            b"JSON",
            b"The DID Document to store in GNUNET",
            self.document.clone(),
        ));
        options.add(helpers::string(
            b'e',
            b"ego",
            b"EGO",
            b"The name of the EGO",
            self.ego.clone(),
        ));
        options.add(helpers::string(
            b't',
            b"expiration-time",
            b"TIME",
            b"The time until the DID Document is going to expire (e.g. 5d)",
            self.expiration.clone(),
        ));
        options
    }

    fn listing(&self) -> Result<Listing> {
        if self.show_all.get()? != 0 {
            Ok(Listing::All)
        } else if self.show.get()? != 0 {
            Ok(Listing::Prefix(self.ego("Show requires an ego option")?))
        } else {
            Ok(Listing::None)
        }
    }

    fn action(&self) -> Result<Action> {
        if self.replace.get()? != 0 {
            return self.publish(host::PublishMode::Replace);
        }
        if self.get.get()? != 0 {
            let did = self.did.get()?.ok_or("Set DID option to resolve DID")?;
            return Ok(Action::Resolve(host::did::Did::parse(
                std::str::from_utf8(&did)?,
            )?));
        }
        if self.remove.get()? != 0 {
            return Ok(Action::Remove(self.ego("Remove requires an ego option")?));
        }
        if self.create.get()? != 0 {
            return self.publish(host::PublishMode::Create);
        }
        Ok(Action::None)
    }

    fn ego(&self, missing: &'static str) -> Result<Vec<u8>> {
        let ego = self.ego.get()?.ok_or(missing)?;
        if ego.len() > host::identity::Limits::default().name_bytes {
            return Err("DID ego exceeds its byte bound".into());
        }
        Ok(ego)
    }

    fn publish(&self, mode: host::PublishMode) -> Result<Action> {
        let document = self.document.get()?.map(Zeroizing::new);
        if document
            .as_ref()
            .is_some_and(|body| body.len() > host::Limits::default().document_bytes)
        {
            return Err("DID document exceeds its byte bound".into());
        }
        let expiration = self.expiration.get()?;
        if mode == host::PublishMode::Replace && (document.is_none() || expiration.is_none()) {
            return Err(
                "Set the DID Document and expiration time argument to replace the DID Document"
                    .into(),
            );
        }
        let ego = self.ego("Set the Ego argument to manage a DID Document")?;
        let expiration = match expiration {
            Some(text) => gnunet_config::parse_relative_time(&text)
                .map_err(|_| "Failed to read given expiration time")?,
            None => host::did::DEFAULT_EXPIRATION_MICROS,
        };
        Ok(Action::Publish {
            ego,
            document,
            expiration,
            mode,
        })
    }
}

pub(crate) fn run() -> Result<()> {
    let arguments = Arguments::new();
    let Some((prepared, clock)) = crate::configured::prepare(
        b"gnunet-did",
        b"Manage Decentralized Identities (DIDs)",
        arguments.options(),
    )?
    else {
        return Ok(());
    };
    let listing = arguments.listing()?;
    let action = arguments.action()?;
    if matches!(listing, Listing::None) && matches!(action, Action::None) {
        return Ok(());
    }
    crate::configured::run(
        prepared.main().config,
        clock,
        [b"identity", b"namestore", b"gns"],
        |[identity, namestore, gns]| {
            let sources = host::Sources {
                clock: identity.clock(),
                identity: (!matches!(listing, Listing::None)
                    || matches!(action, Action::Remove(_) | Action::Publish { .. }))
                .then_some(identity),
                namestore: matches!(action, Action::Remove(_) | Action::Publish { .. })
                    .then_some(namestore),
                gns: matches!(action, Action::Resolve(_)).then_some(gns),
            };
            execute(listing, action, sources)
        },
    )
}

async fn execute(listing: Listing, action: Action, sources: host::Sources) -> Result<()> {
    let identity = host::identity::Instance::new();
    let namestore = host::ns::Instance::new();
    let mut gns = host::gns::Instance::new();
    let mut client = host::Client::new(
        host::Instances {
            identity: &identity,
            namestore: &namestore,
            gns: &mut gns,
        },
        sources,
        host::Limits::default(),
    )?;
    let deadline = client.deadline(TIMEOUT)?;
    let interrupt = tokio::signal::ctrl_c();
    tokio::pin!(interrupt);
    if !matches!(listing, Listing::None) {
        let rows = client
            .show_all(&deadline, interrupt.as_mut(), |_| {})
            .await?;
        let mut out = io::stdout().lock();
        for row in rows {
            if matches!(&listing, Listing::Prefix(prefix) if !row.name.starts_with(prefix)) {
                continue;
            }
            out.write_all(&row.name)?;
            writeln!(out, ":\n\t{}", did_text(row.did)?)?;
        }
        out.flush()?;
    }
    match action {
        Action::None => {}
        Action::Resolve(did) => {
            let document = client
                .resolve(did, &deadline, interrupt.as_mut(), |_| {})
                .await?;
            let mut out = io::stdout().lock();
            out.write_all(document.json())?;
            out.write_all(b"\n")?;
            out.flush()?;
        }
        Action::Remove(ego) => {
            client
                .remove(&ego, &deadline, interrupt.as_mut(), |_| {})
                .await?;
        }
        Action::Publish {
            ego,
            document,
            expiration,
            mode,
        } => {
            let mut entropy = OsEntropy { failure: None };
            let result = client
                .publish(
                    host::Publish {
                        ego: &ego,
                        document: document.as_deref().map(Vec::as_slice),
                        expiration_micros: expiration,
                        mode,
                        create_ego: mode == host::PublishMode::Create && document.is_none(),
                    },
                    &mut entropy,
                    &deadline,
                    interrupt.as_mut(),
                    |_| {},
                )
                .await;
            if let Some(error) = entropy.failure {
                return Err(error.into());
            }
            let did = did_text(result?)?;
            let verb = if mode == host::PublishMode::Create {
                "created"
            } else {
                "replaced"
            };
            let mut out = io::stdout().lock();
            writeln!(out, "DID has been {verb}.\n{did}")?;
            out.flush()?;
        }
    }
    Ok(())
}
