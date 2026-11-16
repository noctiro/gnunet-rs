//! Autoconfiguration proposals and finite reachability results.
use super::{AutoOptions, Failure, Signals, diagnostic, interval, output};
use crate::{Limits as TestLimits, Outcome, Progress as TestProgress, Test};
use gnunet_client_host::{EndpointSource, LiveConfiguration, resolution::SharedResolution};
use gnunet_config::Configuration;
use gnunet_nat_client_host::{self as client, AutoProgress, AutoQuery, Deadlines, Instance};
use gnunet_nat_host::deadline::Bounds;
use gnunet_program_host::reporting::Reporter;
use gnunet_service_runtime::clock::RuntimeClock;
use std::{future::poll_fn, path::PathBuf, sync::Arc, task::Poll};
pub(super) async fn auto(
    config: &Configuration,
    filename: Option<PathBuf>,
    resolution: SharedResolution,
    clock: Arc<dyn RuntimeClock>,
    options: AutoOptions,
    signals: &mut Signals,
    reports: &Reporter,
) -> Result<(), Failure> {
    if !options.configure && options.section.is_none() {
        return Err("select --auto and/or --section".into());
    }
    if options.write && !options.configure {
        return Err("--write requires --auto".into());
    }
    if options.section.is_some() && !matches!(options.protocol, Some(6 | 17)) {
        return Err("--section test requires exactly --tcp or --udp".into());
    }
    let instance = Instance::new();
    let timeout = interval(config, b"TEST_TIMEOUT", 30_000_000)?;
    let until = Bounds::after(&*clock, timeout)?;
    let mut query = if options.configure {
        let source = EndpointSource::live(
            LiveConfiguration::new(config.duplicate()?),
            b"nat-auto",
            resolution.clone(),
        );
        Some(AutoQuery::from_configuration(
            &instance,
            source,
            config,
            Deadlines {
                send_until: until.expires,
                first_input_until: None,
                until: until.expires,
            },
            Default::default(),
        )?)
    } else {
        None
    };
    let mut test = if let Some(section) = &options.section {
        Some(
            Test::from_configuration(
                &instance,
                config,
                resolution,
                section,
                options.protocol.ok_or("missing protocol")?,
                timeout,
                TestLimits::default(),
            )
            .await?,
        )
    } else {
        None
    };
    let mut failures = Vec::new();
    let mut query_done = query.is_none();
    let mut test_done = test.is_none();
    while !query_done || !test_done {
        #[expect(
            clippy::large_enum_variant,
            reason = "Carry already-owned query/test terminal receipts without a new allocation after source close"
        )]
        enum Step<'id> {
            Stop,
            Query(AutoProgress<'id>),
            Test(TestProgress<'id>),
        }
        let step = poll_fn(|cx| {
            if let Poll::Ready(result) = signals.poll_stop(cx) {
                result?;
                return Poll::Ready(Ok::<_, Failure>(Step::Stop));
            }
            if !query_done
                && let Some(query) = &mut query
                && let Poll::Ready(result) = query.poll(cx, None)
            {
                return Poll::Ready(result.map(Step::Query).map_err(Into::into));
            }
            if !test_done
                && let Some(test) = &mut test
                && let Poll::Ready(result) = test.poll(cx, None)
            {
                return Poll::Ready(result.map(Step::Test));
            }
            Poll::Pending
        })
        .await?;
        match step {
            Step::Stop => {
                if let Some(query) = &mut query {
                    let _end = query.cancel();
                }
                if let Some(test) = &mut test {
                    let _end = test.cancel();
                }
                return Ok(());
            }
            Step::Query(AutoProgress::ResultReady(..)) => {
                let result = query
                    .as_mut()
                    .and_then(AutoQuery::take_result)
                    .ok_or("missing actual original NATauto result")?;
                let response = result.response()?;
                output(format_args!(
                    "NAT auto actual status={} type={}; proposal does not prove connectivity",
                    response.status.0, response.nat_type.0
                ))?;
                if response.status != client::auto_ipc::Status::SUCCESS {
                    failures.push(format!("NATauto actual status{}", response.status.0));
                } else {
                    let mut diff = Configuration::create(
                        Arc::new(config.project_data().clone()),
                        Default::default(),
                    )?;
                    diff.deserialize(response.configuration_diff, None)?;
                    let mut updated = config.duplicate()?;
                    let mut changed = false;
                    for (section, key, value) in diff.entries() {
                        if section.eq_ignore_ascii_case(b"nat") {
                            updated.set_value(section, key, Some(value))?;
                            changed = true;
                            output(format_args!(
                                "suggested NAT {}={}",
                                String::from_utf8_lossy(key),
                                String::from_utf8_lossy(value)
                            ))?;
                        }
                    }
                    if options.write && changed {
                        let path = filename
                            .as_ref()
                            .ok_or("no selected configuration filename for --write")?;
                        updated.set_value(b"ARM", b"CONFIG", None)?;
                        let mut defaults = Configuration::create(
                            Arc::new(config.project_data().clone()),
                            Default::default(),
                        )?;
                        defaults.load(None)?;
                        defaults.write_diffs(&updated, path)?;
                        output(format_args!(
                            "configuration changes actually written to {}",
                            path.display()
                        ))?;
                    }
                }
                query_done = true;
            }
            Step::Query(AutoProgress::Ended(end)) => {
                failures.push(format!("NATauto original source ended: {:?}", end.cause));
                query_done = true;
            }
            Step::Query(AutoProgress::Closed) => {
                failures.push("NATauto closed without an actual result".into());
                query_done = true;
            }
            Step::Test(TestProgress::Ended(end)) => {
                if let Some(original) = &end.registration {
                    diagnostic(
                        reports,
                        format_args!("NAT test original registration end: {:?}", original.source),
                    );
                }
                match end.outcome {
                    Outcome::Received(o) => output(format_args!(
                        "NAT test received original challenge: target={} transport={:?} address={:?}; unauthenticated network-path observation",
                        o.target(),
                        o.transport(),
                        o.address()
                    ))?,
                    Outcome::Timeout => failures.push("NAT test original deadline elapsed".into()),
                    Outcome::Cancelled => failures.push("NAT test cancelled".into()),
                    Outcome::Failed(e) => failures.push(format!("NAT test failed: {e}")),
                }
                test_done = true;
            }
            Step::Test(TestProgress::Closed) => {
                failures.push("NAT test closed without an original terminal result".into());
                test_done = true;
            }
            _ => {}
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; ").into())
    }
}
