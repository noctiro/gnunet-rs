//! Installed file and directory publication over configured FS and DATASTORE.

pub(super) mod namespace;
mod preview;
mod simulation;

use super::{
    Execution, FsAccess, Gate, RootKeywords, Style, execute, settings::RecordMetadata,
    source_is_tree,
};
use gnunet::{
    fs::{Keywords, Limits as UriLimits, Uri},
    fs_host::{
        Control,
        extraction::ManualMetadata,
        ipc::EndpointSource,
        network::{BlockOptions, ublock::UblockOptions},
    },
    types::AbsoluteTime,
};
use gnunet_program_host::{
    getopt::{Argument, Context, Options, Output, Spec},
    helpers::{self, Target},
    program,
};
use std::{
    cell::RefCell,
    error::Error,
    future::{Future, poll_fn},
    rc::Rc,
    sync::{Arc, atomic::Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type Result<T> = std::result::Result<T, Box<dyn Error>>;
const INTERVAL: Duration = Duration::from_secs(300);

struct Arguments {
    anonymity: Target<u32>,
    priority: Target<u32>,
    replication: Target<u32>,
    full: Target<i32>,
    disabled: Target<i32>,
    creation_time: Target<i32>,
    extract_only: Target<i32>,
    simulate_only: Target<i32>,
    metadata: Rc<RefCell<ManualMetadata>>,
    keywords: Rc<RefCell<RootKeywords>>,
    uri: Target<Option<Vec<u8>>>,
    pseudonym: Target<Option<Vec<u8>>>,
    identifier: Target<Option<Vec<u8>>>,
    next: Target<Option<Vec<u8>>>,
    verbose: Target<u32>,
}

impl Arguments {
    fn new() -> Self {
        Self {
            anonymity: Target::new(1),
            priority: Target::new(365),
            replication: Target::new(1),
            full: Target::new(0),
            disabled: Target::new(0),
            creation_time: Target::new(0),
            extract_only: Target::new(0),
            simulate_only: Target::new(0),
            metadata: Rc::new(RefCell::new(Default::default())),
            keywords: Rc::new(RefCell::new(Default::default())),
            uri: Target::new(None),
            pseudonym: Target::new(None),
            identifier: Target::new(None),
            next: Target::new(None),
            verbose: Target::new(0),
        }
    }

    fn options(&self) -> Options<'static> {
        let mut options = Options::new();
        options.add(helpers::verbose(self.verbose.clone()));
        options.add(helpers::uint(
            b'a',
            b"anonymity",
            b"LEVEL",
            b"Set sender anonymity",
            self.anonymity.clone(),
        ));
        options.add(helpers::uint(
            b'p',
            b"priority",
            b"PRIORITY",
            b"Set content priority",
            self.priority.clone(),
        ));
        options.add(helpers::uint(
            b'r',
            b"replication",
            b"LEVEL",
            b"Set the replication level",
            self.replication.clone(),
        ));
        options.add(helpers::flag(
            b'n',
            b"noindex",
            b"Fully insert encrypted content instead of indexing files",
            self.full.clone(),
        ));
        options.add(helpers::flag(
            b'D',
            b"disable-extractor",
            b"Disable automatic metadata and keyword extraction",
            self.disabled.clone(),
        ));
        options.add(helpers::flag(
            b'E',
            b"enable-creation-time",
            b"Add a publication date to object metadata",
            self.creation_time.clone(),
        ));
        options.add(helpers::flag(
            b'e',
            b"extract",
            b"Print extracted metadata and keywords without publishing",
            self.extract_only.clone(),
        ));
        options.add(helpers::flag(
            b's',
            b"simulate-only",
            b"Compute publication URIs without storing or indexing content",
            self.simulate_only.clone(),
        ));
        options.add(helpers::string(
            b'u',
            b"uri",
            b"URI",
            b"Publish keywords for an existing FS URI",
            self.uri.clone(),
        ));
        options.add(helpers::string(
            b'P',
            b"pseudonym",
            b"NAME",
            b"Publish into the namespace of this Identity ego",
            self.pseudonym.clone(),
        ));
        options.add(helpers::string(
            b't',
            b"this",
            b"ID",
            b"Set the identifier of this namespace publication",
            self.identifier.clone(),
        ));
        options.add(helpers::string(
            b'N',
            b"next",
            b"ID",
            b"Set the identifier of the next namespace version",
            self.next.clone(),
        ));
        let metadata = self.metadata.clone();
        options.push(
            Spec {
                short: b'm',
                name: b"meta",
                argument_help: Some(b"TYPE:VALUE"),
                description: Some(b"Add one top-level metadata item; repeat for more items"),
                argument: Argument::Required,
                mandatory: false,
                exclusive: false,
            },
            move |_: Context<'_>, _: &[u8], value: Option<&[u8]>, out: &mut Output<'_>| {
                let parsed = value.is_some_and(|value| {
                    metadata
                        .try_borrow_mut()
                        .is_ok_and(|mut metadata| metadata.push(value).is_ok())
                });
                if parsed {
                    1
                } else {
                    let _diagnostic =
                        out.error(b"Invalid or excessive publication metadata.\n", &[]);
                    -1
                }
            },
        );
        let keywords = self.keywords.clone();
        options.push(
            Spec {
                short: b'k',
                name: b"key",
                argument_help: Some(b"KEYWORD"),
                description: Some(
                    b"Add one top-level keyword, with an optional leading + for mandatory searches",
                ),
                argument: Argument::Required,
                mandatory: false,
                exclusive: false,
            },
            move |_: Context<'_>, _: &[u8], value: Option<&[u8]>, out: &mut Output<'_>| {
                let parsed = value.is_some_and(|value| {
                    let (term, mandatory) = keyword(value);
                    keywords
                        .try_borrow_mut()
                        .is_ok_and(|mut keywords| keywords.push(term, mandatory).is_ok())
                });
                if parsed {
                    1
                } else {
                    let _diagnostic =
                        out.error(b"Invalid or excessive publication keyword.\n", &[]);
                    -1
                }
            },
        );
        options
    }
}

fn keyword(value: &[u8]) -> (&[u8], bool) {
    let literal = value.strip_prefix(b"+");
    let term = literal.unwrap_or(value);
    let term = match term {
        [b'"', quoted @ .., b'"'] if !quoted.is_empty() => quoted,
        _ => term,
    };
    (term, literal.is_some())
}

pub(crate) fn run() -> Result<()> {
    let expires = expiration(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())?;
    let arguments = Arguments::new();
    let Some((prepared, clock)) = crate::configured::prepare(
        b"gnunet-publish",
        b"Publish a file, a directory, or keywords for an existing FS URI. Files are indexed unless -n/--noindex is selected.",
        arguments.options(),
    )? else { return Ok(()); };
    let main = prepared.main();
    let blocks = BlockOptions {
        anonymity: arguments.anonymity.get()?,
        priority: arguments.priority.get()?,
        replication: arguments.replication.get()?,
        expiration: expires,
    };
    let manual = std::mem::take(
        &mut *arguments
            .metadata
            .try_borrow_mut()
            .map_err(|_| "publication metadata option is still owned by the parser")?,
    );
    let root_keywords = std::mem::take(
        &mut *arguments
            .keywords
            .try_borrow_mut()
            .map_err(|_| "publication keyword option is still owned by the parser")?,
    );
    let extract_only = arguments.extract_only.get()? != 0;
    let simulate_only = arguments.simulate_only.get()? != 0;
    let verbose = arguments.verbose.get()?;
    let namespace = namespace::Selection::new(
        arguments.pseudonym.get()?,
        arguments.identifier.get()?,
        arguments.next.get()?,
    )?;
    let graph_root = if extract_only || simulate_only {
        None
    } else {
        namespace
            .as_ref()
            .map(|selected| selected.graph_root(main.config))
            .transpose()?
            .flatten()
    };
    if let Some(text) = arguments.uri.get()? {
        if extract_only {
            return Err("gnunet-publish cannot extract metadata from an FS URI".into());
        }
        if simulate_only {
            return Err(
                "gnunet-publish -s requires a filename or directory instead of an FS URI".into(),
            );
        }
        if !main.arguments.is_empty() {
            return Err("gnunet-publish cannot combine -u with a filename".into());
        }
        if root_keywords.is_empty() && namespace.is_none() {
            return Err("gnunet-publish -u requires at least one -k keyword".into());
        }
        let uri = Uri::parse(&text, UriLimits::default())?;
        let terms = root_keywords.terms()?;
        let keywords = (!terms.is_empty())
            .then(|| Keywords::new(&terms))
            .transpose()?;
        let mut metadata = RecordMetadata::new(manual, None)?;
        let plan = metadata.plan()?;
        let hard = hard_deadline()?;
        return crate::configured::run(
            main.config,
            clock,
            [b"datastore", b"identity"],
            move |[store, identity]| async move {
                publish_uri(UriPublication {
                    store,
                    identity,
                    keywords,
                    uri,
                    metadata: plan.as_ref(),
                    blocks,
                    namespace,
                    graph_root,
                    hard,
                })
                .await
            },
        );
    }
    let [path] = main.arguments else {
        return Err("gnunet-publish requires exactly one filename".into());
    };
    let source = program::native_path(path)?.into_owned();
    source_is_tree(&source)?;
    let indexed = arguments.full.get()? == 0;
    let mut metadata = crate::fs::metadata_options::Arguments::default();
    metadata.disabled = arguments.disabled.get()? != 0;
    let creation_time = arguments.creation_time.get()? != 0;
    crate::fs::output::with_stdout("gnunet-publish", true, |out| {
        let hard = hard_deadline()?;
        out.deadline(hard);
        let metadata = metadata.select_configured(main.config)?.with_manual(manual);
        if extract_only || simulate_only {
            let creation_time = creation_time
                .then(|| clock.sample().map(|sample| sample.now))
                .transpose()?;
            let namespace_uri = if let Some(selected) = namespace {
                crate::configured::run(
                    main.config,
                    clock,
                    [b"identity"],
                    move |[identity]| async move {
                        let until = remaining_deadline(&identity, hard)?.as_micros();
                        let mut gate = Gate::new(hard)?;
                        if extract_only {
                            drop(selected.lookup(identity, until, &mut gate).await?);
                            Ok(None)
                        } else {
                            Ok(Some(
                                selected
                                    .authorize(identity, until, &mut gate)
                                    .await?
                                    .uri()?,
                            ))
                        }
                    },
                )?
            } else {
                None
            };
            return if extract_only {
                preview::run(
                    source,
                    hard,
                    metadata,
                    creation_time,
                    &root_keywords,
                    verbose,
                    out,
                )
            } else {
                simulation::run(
                    source,
                    hard,
                    metadata,
                    creation_time,
                    namespace_uri.as_deref(),
                    verbose,
                    out,
                )
            };
        }
        crate::configured::run(
            main.config,
            clock,
            [b"fs", b"datastore", b"identity"],
            move |[fs, store, identity]| async move {
                let deadline = remaining_deadline(&store, hard)?;
                let creation_time = creation_time
                    .then(|| store.clock().sample().map(|sample| sample.now))
                    .transpose()?;
                if Instant::now() >= hard {
                    return Err("configuration exceeded the original publication deadline".into());
                }
                let namespace = match namespace {
                    Some(selected) => {
                        let until = remaining_deadline(&identity, hard)?.as_micros();
                        let authority = selected
                            .authorize(identity, until, &mut Gate::new(hard)?)
                            .await?;
                        Some((authority, graph_root))
                    }
                    None => None,
                };
                execute(
                    Execution {
                        source,
                        state: None,
                        hard,
                        store,
                        fs: FsAccess::configured(fs, indexed, blocks.anonymity),
                        deadline,
                        blocks,
                        metadata,
                        root_keywords,
                        creation_time,
                        style: Style::Official,
                        namespace,
                        verbose,
                    },
                    out,
                )
                .await
            },
        )
    })
}

fn hard_deadline() -> Result<Instant> {
    Instant::now()
        .checked_add(INTERVAL)
        .ok_or_else(|| "publication native deadline overflow".into())
}

struct UriPublication<'a> {
    store: EndpointSource,
    identity: EndpointSource,
    keywords: Option<Keywords<'a>>,
    uri: Uri<'a>,
    metadata: Option<&'a gnunet::fs::metadata::Plan<'a>>,
    blocks: BlockOptions,
    namespace: Option<namespace::Selection>,
    graph_root: Option<std::path::PathBuf>,
    hard: Instant,
}

fn remaining_deadline(store: &EndpointSource, hard: Instant) -> Result<AbsoluteTime> {
    let remaining = hard
        .checked_duration_since(Instant::now())
        .ok_or("configuration exceeded the original publication deadline")?;
    super::target(store, u64::try_from(remaining.as_micros())?)
}

async fn publish_uri(request: UriPublication<'_>) -> Result<()> {
    let UriPublication {
        store,
        identity,
        keywords,
        uri,
        metadata,
        blocks,
        namespace,
        graph_root,
        hard,
    } = request;
    let mut gate = Gate::new(hard)?;
    let namespace = match namespace {
        Some(selected) => {
            let until = remaining_deadline(&identity, hard)?.as_micros();
            Some(selected.authorize(identity, until, &mut gate).await?)
        }
        None => None,
    };
    let options = UblockOptions::new(remaining_deadline(&store, hard)?, blocks);
    if let Some(keywords) = keywords {
        publish_uri_keywords(
            store.duplicate()?,
            keywords,
            uri,
            metadata,
            options,
            &mut gate,
        )
        .await?;
    }
    if let Some(namespace) = namespace {
        namespace
            .publish(
                store,
                uri,
                metadata,
                options,
                graph_root.as_deref(),
                &mut gate,
            )
            .await?;
    }
    Ok(())
}

async fn publish_uri_keywords(
    store: EndpointSource,
    keywords: Keywords<'_>,
    uri: Uri<'_>,
    metadata: Option<&gnunet::fs::metadata::Plan<'_>>,
    options: UblockOptions,
    gate: &mut Gate,
) -> Result<()> {
    let stop = Arc::clone(&gate.stop);
    let hard = gate.hard;
    let writing = crate::fs::publication::store_keywords(
        store,
        keywords,
        uri,
        metadata,
        options,
        move |_| {
            if stop.load(Ordering::Acquire) || Instant::now() >= hard {
                Control::Cancel
            } else {
                Control::Continue
            }
        },
    );
    let mut writing = std::pin::pin!(writing);
    let outcome = poll_fn(|cx| {
        gate.poll(cx);
        writing.as_mut().poll(cx)
    })
    .await??;
    if let Some(error) = gate.signal_error.take() {
        return Err(error.into());
    }
    if let Some(error) = outcome.cleanup {
        return Err(error.into());
    }
    Ok(())
}

fn days_in_year(year: u64) -> u64 {
    if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) {
        366
    } else {
        365
    }
}

// January 1 UTC of the current UTC year plus two. A full Gregorian cycle
// keeps the search for the current year bounded for any representable input.
fn expiration(now: u64) -> Result<AbsoluteTime> {
    const DAY_SECONDS: u64 = 86_400;
    const CYCLE_DAYS: u64 = 146_097;
    let days = now / DAY_SECONDS;
    let mut start = days / CYCLE_DAYS * CYCLE_DAYS;
    let mut year = 1970 + days / CYCLE_DAYS * 400;
    while days - start >= days_in_year(year) {
        start += days_in_year(year);
        year += 1;
    }
    let time = (start + days_in_year(year) + days_in_year(year + 1))
        .checked_mul(DAY_SECONDS * 1_000_000)
        .ok_or("publication expiration is not representable")?;
    Ok(AbsoluteTime::from_micros(time))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn official_publish_treats_each_keyword_option_as_one_literal() {
        assert_eq!(keyword(b"two  words"), (b"two  words".as_slice(), false));
        assert_eq!(keyword(b"+\"two words\""), (b"two words".as_slice(), true));
        assert_eq!(keyword(b"++literal"), (b"+literal".as_slice(), true));
    }

    #[test]
    fn official_publish_expiration_follows_the_utc_year_boundary() -> Result<()> {
        for (at, expected) in [
            (946_684_799, 978_307_200_000_000),
            (946_684_800, 1_009_843_200_000_000),
        ] {
            let actual = expiration(at)?.as_micros();
            if actual != expected {
                return Err(
                    format!("at {at}, expected expiration {expected}, got {actual}").into(),
                );
            }
        }
        Ok(())
    }
}
