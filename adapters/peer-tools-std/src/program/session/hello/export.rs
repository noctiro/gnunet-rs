//! Public identity observation, HELLO export and original PILS re-signing.
use super::super::{
    ADDRESS_BYTES, Failure, Instant, Io, Mode, Owners, RuntimeClock, Settings, Signals, URL_BYTES,
    Wake, Zeroizing, buffer, choose, diagnostic, hello_limits, output, peer_text, pils, print_pils,
};
use gnunet_hello::{AbsoluteTime, Hello};
use gnunet_pils::client::{Completion, Inbound, KeyTarget, LocalKeyStatus, OperationId};
use std::sync::Arc;
fn encoded(hello: Hello<'_>, binary: bool) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let n = if binary {
        hello.message_len()?
    } else {
        hello.url_len()?
    };
    if n > if binary { 65535 } else { URL_BYTES } {
        return Err("public HELLO output exceeds configured native/text width".into());
    }
    let mut out = buffer(n + usize::from(!binary))?;
    if binary {
        hello.encode_message(&mut out)?;
    } else {
        hello.write_url(&mut out[..n])?;
        out[n] = b'\n';
    }
    Ok(out)
}
struct SignedJob<'id> {
    operation: OperationId<'id>,
    identity: gnunet_pils::client::Identity<'id>,
    expiry: AbsoluteTime,
    announcement: gnunet_service_runtime::framing::OwnedFrame,
}
pub(crate) async fn observe_pils<'id>(
    owners: &mut Owners<'id>,
    signals: &mut Signals,
    stdout: &mut Io,
    clock: &Arc<dyn RuntimeClock>,
    settings: &Settings,
    until: Instant,
) -> Result<(), Failure> {
    let reports = owners.resolver.reports.clone();
    let mut scratch = buffer(if settings.mode == Mode::Export {
        ADDRESS_BYTES
    } else {
        0
    })?;
    let mut builder_bytes = buffer(
        if settings.mode == Mode::Export && settings.expiry.is_some() {
            ADDRESS_BYTES
        } else {
            0
        },
    )?;
    let mut job: Option<SignedJob<'id>> = None;
    let mut observations = 0u64;
    let mut first = false;
    loop {
        let client = owners.pils.as_mut().ok_or("PILS owner absent")?;
        let event = match choose(
            client.drive(Some(until)),
            &mut owners.resolver,
            Some(signals),
            until,
            first,
        )
        .await?
        {
            Wake::Provider(event) => event?,
            Wake::Resolver => {
                first = !first;
                continue;
            }
            Wake::Signal => {
                return if settings.mode == Mode::Identity && !settings.once {
                    Ok(())
                } else {
                    Err("finite public-peer action canceled before its output completed".into())
                };
            }
            Wake::Deadline => {
                return if settings.mode == Mode::Identity && !settings.once {
                    Ok(())
                } else {
                    Err("actual PILS public observation/signature was not received before original deadline".into())
                };
            }
        };
        first = !first;
        print_pils(&reports, &event);
        match event {
            pils::Progress::Inbound(Inbound::Identity {
                identity,
                identity_changed,
                local_key,
            }) => {
                if local_key != LocalKeyStatus::Disabled {
                    return Err("public-only CLI unexpectedly obtained local-key authority".into());
                }
                observations = observations.saturating_add(1);
                diagnostic(
                    &reports,
                    format_args!(
                        "actual PILS public observation epoch={:?} revision={} changed={} coverage={:?}; observation-count={observations}",
                        identity.epoch(),
                        identity.revision(),
                        identity_changed,
                        identity.coverage()
                    ),
                );
                if settings.mode == Mode::Identity {
                    let text = peer_text(identity.peer().as_bytes())?;
                    output(stdout, &text, &mut owners.resolver, signals, until).await?;
                    if settings.once {
                        return Ok(());
                    }
                    continue;
                }
                if let Some(original) = &job {
                    if original.identity.peer() != identity.peer()
                        || original.identity.epoch() != identity.epoch()
                    {
                        return Err("original PILS signer source/key changed; original request is not replayed".into());
                    }
                    continue;
                }
                let client = owners.pils.as_mut().ok_or("PILS owner absent")?;
                if client.identity() != Some(identity) {
                    return Err("PILS identity event is not the current original source".into());
                }
                let bytes = client
                    .announcement()
                    .ok_or("current PILS announcement missing")?;
                let announced = gnunet_wire::official::pils::PeerUpdate::decode(bytes)?;
                let hello = Hello::parse_block(announced.block, &mut scratch, hello_limits())?;
                if hello.peer() != identity.peer() {
                    return Err("public HELLO/PILS identity mismatch".into());
                }
                if let Some(relative) = settings.expiry {
                    let expiration = AbsoluteTime::from_micros(
                        clock.sample()?.now.as_micros().saturating_add(relative),
                    );
                    // Fallible retention precedes original SIGN admission.
                    let announcement =
                        gnunet_service_runtime::framing::OwnedFrame::copy_from(bytes)?;
                    let builder = hello.to_builder(&mut builder_bytes, hello_limits())?;
                    let operation =
                        client.sign_hello(&builder, expiration, KeyTarget::Exact(identity))?;
                    diagnostic(
                        &reports,
                        format_args!(
                            "actual PILS HELLO purpose7 admitted operation={operation:?} epoch={:?}; no signature result yet",
                            identity.epoch()
                        ),
                    );
                    job = Some(SignedJob {
                        operation,
                        identity,
                        expiry: expiration,
                        announcement,
                    });
                } else {
                    let bytes = encoded(hello, settings.binary)?;
                    output(stdout, &bytes, &mut owners.resolver, signals, until).await?;
                    return Ok(());
                }
            }
            pils::Progress::Inbound(Inbound::Complete(completion)) => {
                let original = job
                    .take()
                    .ok_or("unexpected crypto result on public-only PILS observation")?;
                match completion {
                    Completion::Signature {
                        operation,
                        peer,
                        signature,
                        announced,
                    } => {
                        if operation != original.operation
                            || peer != original.identity.peer()
                            || !announced.is_some_and(|identity| {
                                identity.peer() == peer
                                    && identity.epoch() == original.identity.epoch()
                            })
                        {
                            return Err(
                                "original PILS signature/source/signer binding refused".into()
                            );
                        }
                        let current = owners
                            .pils
                            .as_ref()
                            .and_then(pils::Client::identity)
                            .ok_or("PILS original signer no longer current")?;
                        if current.peer() != peer || current.epoch() != original.identity.epoch() {
                            return Err("original PILS signer retired before export".into());
                        }
                        let update = gnunet_wire::official::pils::PeerUpdate::decode(
                            original.announcement.bytes(),
                        )?;
                        let original_hello =
                            Hello::parse_block(update.block, &mut scratch, hello_limits())?;
                        let builder =
                            original_hello.to_builder(&mut builder_bytes, hello_limits())?;
                        // The SDK verified the retained purpose bytes and original operation.
                        let hello = builder.with_signature(peer, signature, original.expiry);
                        let bytes = encoded(hello, settings.binary)?;
                        output(stdout, &bytes, &mut owners.resolver, signals, until).await?;
                        return Ok(());
                    }
                    Completion::Failed {
                        operation,
                        kind,
                        reason,
                    } => {
                        return Err(format!(
                            "PILS operation {operation:?} {kind:?} failed: {reason:?}"
                        )
                        .into());
                    }
                    Completion::Decapsulated { .. } | Completion::Ecdh { .. } => {
                        return Err(
                            "unexpected non-signature completion on public HELLO export".into()
                        );
                    }
                }
            }
            pils::Progress::Lost { .. } if job.is_some() => {
                return Err(
                    "original PILS signing MQ lost before result; no automatic sign replay".into(),
                );
            }
            pils::Progress::Closed => {
                return Err("PILS source closed before requested public result".into());
            }
            _ => {}
        }
    }
}
