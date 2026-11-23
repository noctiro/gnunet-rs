//! Offline URI generation with the regular publication encoder.
use super::super::progress;
use super::{Gate, Result};
use gnunet::{
    fs_host::{
        Buffers, Control,
        extraction::{self, MetadataSettings},
        publication::{
            Limits,
            auto_prepare::{self, Policy},
            plan::tree::{Event, Observer},
        },
    },
    types::AbsoluteTime,
};
use std::{
    future::{Future, poll_fn},
    io::{self, Write},
    path::PathBuf,
    sync::{Arc, atomic::Ordering},
    time::Instant,
};

pub(super) fn run(
    source: PathBuf,
    hard: Instant,
    metadata: MetadataSettings,
    creation_time: Option<AbsoluteTime>,
    namespace_uri: Option<&[u8]>,
    verbose: u32,
    out: &mut crate::fs::Output<'_, impl Write>,
) -> Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let mut gate = Gate::new(hard)?;
            let stop = Arc::clone(&gate.stop);
            let input = source.clone();
            let (reporter, updates) = progress::channel(verbose);
            let worker = tokio::task::spawn_blocking(move || {
                let policy = Policy {
                    metadata: extraction::Policy {
                        extract: metadata.automatic_keywords_enabled(),
                        creation_time,
                        ..Default::default()
                    },
                    ..Default::default()
                };
                let mut report = |event: Event<'_>| {
                    reporter
                        .as_ref()
                        .map_or(Control::Continue, |reporter| reporter.report(event))
                };
                let observer: Observer<'_> = (verbose != 0).then_some(&mut report);
                auto_prepare::simulate(
                    &input,
                    &mut Buffers::new(),
                    Limits::default(),
                    policy,
                    metadata,
                    observer,
                    move |_| {
                        if stop.load(Ordering::Acquire) || Instant::now() >= hard {
                            Control::Cancel
                        } else {
                            Control::Continue
                        }
                    },
                )
            });
            let output = progress::drain(updates, &source, out, &mut gate).await;
            let mut worker = std::pin::pin!(worker);
            let outcome = poll_fn(|cx| {
                gate.poll(cx);
                worker.as_mut().poll(cx)
            })
            .await;
            output?;
            if let Some(error) = gate.signal_error {
                return Err(error.into());
            }
            if gate.expired {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "publication simulation deadline elapsed",
                )
                .into());
            }
            if gate.stop.load(Ordering::Acquire) {
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "publication simulation cancelled",
                )
                .into());
            }
            let objects = outcome??;
            let mut encoded = Vec::new();
            for object in objects {
                let uri = object.content.uri();
                encoded.resize(uri.encoded_len()?, 0);
                uri.encode(&mut encoded)?;
                super::super::official_object(out, &source, &object.relative, &encoded)?;
                if object.relative.as_os_str().is_empty()
                    && let Some(uri) = namespace_uri
                {
                    super::super::official_namespace(out, uri)?;
                }
            }
            out.flush()?;
            Ok(())
        })
}
