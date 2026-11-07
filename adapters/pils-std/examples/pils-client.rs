//! Finite native Rust client to an actual PILS endpoint, with no C library backend.
#![expect(
    clippy::print_stdout,
    reason = "Finite observer emits one exact machine-readable terminal record"
)]
use gnunet_crypto::hash512;
use gnunet_hello::{Hello, HelloBuilder, SignatureCoverage};
use gnunet_pils::{
    HelloLimits, Profile,
    client::{
        Completion, Failure, Identity, Inbound, Instance, KeyTarget, LocalKeyStatus, OperationId,
    },
};
use gnunet_pils_host::{
    client::{Client, EndpointSource, Limits, Progress},
    identity::load_existing,
};
use gnunet_session_crypto::exchange::{EcdhePublic, EcdheSecret, kem_encapsulate};
use gnunet_wire::official::{AbsoluteTime, SignaturePurpose};
use std::{
    io::{self, Write},
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::time::Instant;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
#[derive(Default)]
struct Counts {
    connected: usize,
    announcements: usize,
    written: usize,
    complete: usize,
    ignored: usize,
    steps: usize,
    signatures: usize,
    ecdh: usize,
    kem: usize,
    crypto_failures: usize,
    local_refusals: usize,
}
fn require(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(io::Error::other(message).into())
    }
}
fn hello_limits() -> HelloLimits {
    HelloLimits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 65535,
        maximum_addresses: 128,
    }
}
async fn step<'a>(client: &mut Client<'a>, counts: &mut Counts) -> Result<Progress<'a>> {
    let progress = client
        .drive(Some(Instant::now() + Duration::from_secs(5)))
        .await?;
    counts.steps += 1;
    match &progress {
        Progress::Connected(_) => counts.connected += 1,
        Progress::Written(_) => counts.written += 1,
        Progress::Inbound(Inbound::Identity { identity, .. }) => {
            require(
                identity.address_hash() == hash512(&[]),
                "not normal Reference029 empty address hash",
            )?;
            require(
                identity.coverage() == SignatureCoverage::MetadataOnly,
                "wrong normal coverage",
            )?;
            counts.announcements += 1;
        }
        Progress::Inbound(Inbound::Complete(_)) => counts.complete += 1,
        Progress::Inbound(Inbound::Ignored) => counts.ignored += 1,
        Progress::Activity {
            read_bytes,
            written_bytes,
        } => require(
            read_bytes + written_bytes > 0,
            "fake progress without native bytes",
        )?,
        Progress::ConnectRetry { .. } => {}
        Progress::WaitDeadline => {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "native wait expired").into());
        }
        _ => {
            return Err(io::Error::other(
                "unexpected native loss/configuration/close event in direct profile",
            )
            .into());
        }
    }
    require(counts.steps < 10000, "unbounded direct progress loop")?;
    Ok(progress)
}
async fn identity<'a>(client: &mut Client<'a>, counts: &mut Counts) -> Result<Identity<'a>> {
    loop {
        if let Progress::Inbound(Inbound::Identity { identity, .. }) = step(client, counts).await? {
            return Ok(identity);
        }
    }
}
async fn result<'a>(
    client: &mut Client<'a>,
    counts: &mut Counts,
    operation: OperationId<'a>,
) -> Result<Completion<'a>> {
    loop {
        if let Progress::Inbound(Inbound::Complete(done)) = step(client, counts).await? {
            require(
                done.operation() == operation,
                "foreign operation completion",
            )?;
            return Ok(done);
        }
    }
}
fn region(len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0x41; len];
    SignaturePurpose::new(
        35,
        len.checked_sub(8)
            .ok_or_else(|| io::Error::other("small purpose"))?,
    )?
    .encode(&mut bytes)?;
    Ok(bytes)
}
async fn direct<'a>(client: &mut Client<'a>, counts: &mut Counts) -> Result<()> {
    let first = identity(client, counts).await?;
    require(
        client.local_key_status() == LocalKeyStatus::Matched,
        "initial local master mismatch",
    )?;
    let ephemeral = EcdheSecret::from_bytes([7; 32]);
    let peer = EcdhePublic::from_edwards(first.peer().as_bytes())?;
    let (enc, expected_kem) = kem_encapsulate(peer, &ephemeral)?;
    let expected_kem = expected_kem.into_secret_bytes();
    let expected_dh = ephemeral.exchange_hashed(peer)?.into_secret_bytes();
    let payload = region(24)?;
    let op = client.sign(&payload, KeyTarget::Exact(first))?;
    match result(client, counts, op).await? {
        Completion::Signature {
            peer, signature, ..
        } => {
            require(peer == first.peer(), "signer changed")?;
            peer.verify(35, &payload, &signature)?;
            counts.signatures += 1;
        }
        _ => return Err(io::Error::other("signature result absent").into()),
    }
    let op = client.ecdh(*ephemeral.public_key().as_bytes(), KeyTarget::Exact(first))?;
    match result(client, counts, op).await? {
        Completion::Ecdh { key, identity, .. } => {
            require(
                identity.peer() == first.peer() && key.as_bytes() == expected_dh.as_ref(),
                "ECDH mismatch",
            )?;
            counts.ecdh += 1;
        }
        _ => return Err(io::Error::other("ECDH result absent").into()),
    }
    let op = client.decapsulate(*enc.as_bytes(), KeyTarget::Exact(first))?;
    match result(client, counts, op).await? {
        Completion::Decapsulated { key, identity, .. } => {
            require(
                identity.peer() == first.peer() && key.as_bytes() == expected_kem.as_ref(),
                "DHKEM mismatch",
            )?;
            counts.kem += 1;
        }
        _ => return Err(io::Error::other("KEM result absent").into()),
    }
    let mut address_storage = [0; 1024];
    let mut builder = HelloBuilder::new(&mut address_storage, hello_limits());
    builder.add_address(b"tcp://127.0.0.1:1234")?;
    builder.add_address(b"udp://127.0.0.1:1235")?;
    let feed = client.feed_addresses(&builder)?;
    let mut submitted = false;
    let updated = loop {
        match step(client, counts).await? {
            Progress::Written(fact) if fact.operation == feed => {
                require(!fact.canceled, "feed canceled")?;
                submitted = true;
            }
            Progress::Inbound(Inbound::Identity { identity, .. }) => {
                require(
                    submitted,
                    "feed announcement preceded original full local write",
                )?;
                break identity;
            }
            _ => {}
        }
    };
    require(
        updated.peer() == first.peer(),
        "normal feed changed peer unexpectedly",
    )?;
    let hello = gnunet_wire::official::pils::PeerUpdate::decode(
        client
            .announcement()
            .ok_or_else(|| io::Error::other("announcement absent"))?,
    )?;
    let mut scratch = [0; 1024];
    let parsed = Hello::parse_block(hello.block, &mut scratch, hello_limits())?;
    require(parsed.address_count() == 2, "fed addresses absent")?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros();
    let expiration = AbsoluteTime::from_micros(u64::try_from(now)?.saturating_add(60_000_000));
    let op = client.sign_hello(&builder, expiration, KeyTarget::Exact(updated))?;
    match result(client, counts, op).await? {
        Completion::Signature {
            peer, signature, ..
        } => {
            builder
                .with_signature(peer, signature, expiration)
                .verify_signature(Profile::Reference029.hello())?;
            counts.signatures += 1;
        }
        _ => return Err(io::Error::other("HELLO signature absent").into()),
    }
    let canceled = client.ecdh(
        *ephemeral.public_key().as_bytes(),
        KeyTarget::Exact(updated),
    )?;
    loop {
        if let Progress::Written(fact) = step(client, counts).await? {
            require(
                fact.operation == canceled,
                "unexpected write before cancellation",
            )?;
            break;
        }
    }
    client.cancel(canceled)?;
    let op = client.ecdh(
        *ephemeral.public_key().as_bytes(),
        KeyTarget::Exact(updated),
    )?;
    match result(client, counts, op).await? {
        Completion::Ecdh { key, .. } => {
            require(
                key.as_bytes() == expected_dh.as_ref(),
                "post-cancel ECDH mismatch",
            )?;
            counts.ecdh += 1;
        }
        _ => return Err(io::Error::other("post-cancel result absent").into()),
    }
    require(
        counts.ignored == 1,
        "canceled real secret reply not ignored exactly once",
    )?;
    let maximum = region(65527)?;
    let op = client.sign(&maximum, KeyTarget::Exact(updated))?;
    match result(client, counts, op).await? {
        Completion::Signature {
            peer, signature, ..
        } => {
            peer.verify(35, &maximum, &signature)?;
            counts.signatures += 1;
        }
        _ => return Err(io::Error::other("max-size signature absent").into()),
    }
    require(
        client
            .sign(&region(65528)?, KeyTarget::Exact(updated))
            .is_err(),
        "oversize sign admitted",
    )?;
    counts.local_refusals += 1;
    require(
        client.sign(&region(8)?, KeyTarget::Exact(updated)).is_err(),
        "header-only sign admitted",
    )?;
    counts.local_refusals += 1;
    for kem in [false, true] {
        let op = if kem {
            client.decapsulate([0; 32], KeyTarget::ServiceCurrent)?
        } else {
            client.ecdh([0; 32], KeyTarget::ServiceCurrent)?
        };
        match result(client, counts, op).await? {
            Completion::Failed {
                reason: Failure::CryptoRejected,
                ..
            } => counts.crypto_failures += 1,
            _ => return Err(io::Error::other("normal zero crypto failure not explicit").into()),
        }
    }
    require(client.pending() == 0, "pending operations at terminal")?;
    require(
        client.close().iter().all(Option::is_none),
        "close retired unexpected pending operations",
    )?;
    require(
        client.local_key().is_none() && client.local_key_status() == LocalKeyStatus::Disabled,
        "closed local key still published",
    )?;
    Ok(())
}
fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let socket = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::other("SOCKET required"))?,
    );
    let ikm = PathBuf::from(
        args.next()
            .ok_or_else(|| io::Error::other("IKM required"))?,
    );
    let recovery = args.next().is_some_and(|s| s == "recovery");
    require(args.next().is_none(), "unexpected arguments")?;
    let mut instance = Instance::new();
    let mut client = Client::new(
        &mut instance,
        EndpointSource::unix(socket),
        Profile::Reference029,
        Limits {
            io_slice_bytes: 4096,
            ..Limits::default()
        },
        hello_limits(),
    )?;
    client.enable_local_key(load_existing(&ikm)?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut counts = Counts::default();
    if recovery {
        recovery_profile(&runtime, &mut client, &mut counts, &ikm)?;
        return Ok(());
    }
    runtime.block_on(direct(&mut client, &mut counts))?;
    println!(
        "{}",
        serde_json::json!({"kind":"rust-native-PILS-client-direct","status":"passed","profile":"Reference029","connected":counts.connected,"announcements":counts.announcements,"written":counts.written,"completed":counts.complete,"ignored_canceled_secret_results":counts.ignored,"signatures":counts.signatures,"ecdh":counts.ecdh,"kem":counts.kem,"expected_crypto_failures":counts.crypto_failures,"local_refusals":counts.local_refusals,"steps":counts.steps,"largest_sign_request":65535,"feed_local_submitted":1,"feed_remote_ack_claimed":false,"pending":client.pending(),"closed":true,"full_PILS_or_Node_verified":false})
    );
    Ok(())
}

fn checkpoint(phase: &str) -> Result<()> {
    println!("{}", serde_json::json!({"kind":"checkpoint","phase":phase}));
    io::stdout().flush()?;
    Ok(())
}
fn command(expected: &str) -> Result<()> {
    let mut line = String::new();
    let n = io::stdin().read_line(&mut line)?;
    require(
        n > 0 && line.len() < 128 && line.trim() == expected,
        "wrong finite observer control command",
    )
}
async fn initial_feed<'a>(client: &mut Client<'a>, counts: &mut Counts) -> Result<Identity<'a>> {
    let mut storage = [0; 512];
    let mut builder = HelloBuilder::new(&mut storage, hello_limits());
    builder.add_address(b"tcp://127.0.0.1:1234")?;
    builder.add_address(b"udp://127.0.0.1:1235")?;
    let operation = client.feed_addresses(&builder)?;
    let mut written = false;
    loop {
        match step(client, counts).await? {
            Progress::Written(fact) if fact.operation == operation => written = true,
            Progress::Inbound(Inbound::Identity { identity, .. }) => {
                require(written, "feed update before local write")?;
                return Ok(identity);
            }
            _ => {}
        }
    }
}
async fn emit_until_written<'a>(
    client: &mut Client<'a>,
    counts: &mut Counts,
    operation: OperationId<'a>,
) -> Result<()> {
    loop {
        if let Progress::Written(fact) = step(client, counts).await? {
            require(
                fact.operation == operation && !fact.canceled,
                "wrong recovery write",
            )?;
            return Ok(());
        }
    }
}
async fn recovery_result<'a>(
    client: &mut Client<'a>,
    counts: &mut Counts,
    operation: OperationId<'a>,
    old: Identity<'a>,
    changed: bool,
) -> Result<(Completion<'a>, usize, Identity<'a>)> {
    let mut losses = 0;
    let mut announced = None;
    for _ in 0..4096 {
        let event = client
            .drive(Some(Instant::now() + Duration::from_secs(8)))
            .await?;
        counts.steps += 1;
        match event {
            Progress::Lost { epoch, report, .. } => {
                require(epoch == old.epoch(), "lost wrong original MQ")?;
                require(
                    report.retained() == 1 && report.feeds().count() == 0,
                    "wrong recovery operation/feed retention",
                )?;
                require(
                    client.identity().is_none() && client.local_key().is_none(),
                    "old identity survived physical retirement",
                )?;
                losses += 1;
            }
            Progress::Connected(epoch) => {
                require(epoch != old.epoch(), "physical reconnect reused epoch")?;
                counts.connected += 1;
            }
            Progress::ConnectRetry { .. } => {}
            Progress::Written(fact) => {
                require(
                    fact.operation == operation && !fact.canceled,
                    "retry changed original operation",
                )?;
                counts.written += 1;
            }
            Progress::Inbound(Inbound::Identity { identity, .. }) => {
                require(
                    identity.epoch() != old.epoch() && (identity.peer() != old.peer()) == changed,
                    "wrong resumed identity",
                )?;
                require(
                    identity.address_hash() == hash512(&[]),
                    "wrong resumed normal profile",
                )?;
                counts.announcements += 1;
                announced = Some(identity);
            }
            Progress::Inbound(Inbound::Complete(done)) => {
                require(
                    done.operation() == operation && losses == 1,
                    "missing original loss or duplicate completion",
                )?;
                counts.complete += 1;
                return Ok((
                    done,
                    losses,
                    announced
                        .ok_or_else(|| io::Error::other("result preceded new announcement"))?,
                ));
            }
            Progress::Activity {
                read_bytes,
                written_bytes,
            } => require(
                read_bytes + written_bytes > 0,
                "zero native recovery progress",
            )?,
            _ => return Err(io::Error::other("unexpected recovery event").into()),
        }
    }
    Err(io::Error::other("bounded recovery count exceeded").into())
}
fn recovery_profile<'a>(
    runtime: &tokio::runtime::Runtime,
    client: &mut Client<'a>,
    counts: &mut Counts,
    ikm: &std::path::Path,
) -> Result<()> {
    let initial = runtime.block_on(identity(client, counts))?;
    runtime.block_on(initial_feed(client, counts))?;
    checkpoint("ready_same")?;
    command("start_same")?;
    let current = client
        .identity()
        .ok_or_else(|| io::Error::other("identity absent"))?;
    let ephemeral = EcdheSecret::from_bytes([7; 32]);
    let (enc, secret) = kem_encapsulate(
        EcdhePublic::from_edwards(current.peer().as_bytes())?,
        &ephemeral,
    )?;
    let secret = secret.into_secret_bytes();
    let operation = client.decapsulate(*enc.as_bytes(), KeyTarget::Exact(current))?;
    runtime.block_on(emit_until_written(client, counts, operation))?;
    checkpoint("same_written")?;
    command("resume_same")?;
    let (done, same_losses, resumed) =
        runtime.block_on(recovery_result(client, counts, operation, current, false))?;
    match done {
        Completion::Decapsulated { key, identity, .. } => {
            require(
                key.as_bytes() == secret.as_ref() && identity == resumed,
                "replayed KEM result mismatch",
            )?;
            counts.kem += 1;
        }
        _ => return Err(io::Error::other("same-key replay did not complete KEM").into()),
    }
    require(
        client.local_key_status() == LocalKeyStatus::Matched,
        "same-key replay lost local key match",
    )?;
    let update = gnunet_wire::official::pils::PeerUpdate::decode(
        client
            .announcement()
            .ok_or_else(|| io::Error::other("resumed announcement absent"))?,
    )?;
    let mut scratch = [0; 1024];
    require(
        Hello::parse_block(update.block, &mut scratch, hello_limits())?.address_count() == 0,
        "old written feed was silently replayed/inferred applied",
    )?;
    runtime.block_on(initial_feed(client, counts))?;
    checkpoint("ready_changed")?;
    command("start_changed")?;
    let current = client
        .identity()
        .ok_or_else(|| io::Error::other("identity absent"))?;
    let operation = client.ecdh(
        *ephemeral.public_key().as_bytes(),
        KeyTarget::Exact(current),
    )?;
    runtime.block_on(emit_until_written(client, counts, operation))?;
    checkpoint("changed_written")?;
    command("resume_changed")?;
    let (done, changed_losses, new) =
        runtime.block_on(recovery_result(client, counts, operation, current, true))?;
    require(
        matches!(
            done,
            Completion::Failed {
                reason: Failure::KeyChanged,
                ..
            }
        ),
        "changed key was relabelled as original secret",
    )?;
    require(
        client.local_key_status() == LocalKeyStatus::Mismatch && client.local_key().is_none(),
        "old IKM mismatch hidden",
    )?;
    require(
        client.enable_local_key(load_existing(ikm)?)? == LocalKeyStatus::Matched,
        "explicit new IKM did not match",
    )?;
    let payload = region(24)?;
    let operation = client.sign(&payload, KeyTarget::ServiceCurrent)?;
    match runtime.block_on(result(client, counts, operation))? {
        Completion::Signature {
            peer, signature, ..
        } => {
            require(
                peer == new.peer() && peer != initial.peer(),
                "actual new signer not returned",
            )?;
            peer.verify(35, &payload, &signature)?;
            counts.signatures += 1;
        }
        _ => return Err(io::Error::other("new service-current signature absent").into()),
    }
    require(
        client.pending() == 0,
        "recovery terminal still has pending operations",
    )?;
    require(
        client.close().iter().all(Option::is_none),
        "close discarded recovery operations",
    )?;
    println!(
        "{}",
        serde_json::json!({"kind":"rust-native-PILS-client-recovery","status":"passed","same_key_losses":same_losses,"changed_key_losses":changed_losses,"same_key_replay_completed":true,"changed_key_exact_failed":true,"old_master_mismatch_exposed":true,"new_master_explicitly_matched":true,"old_written_feed_not_assumed_applied":true,"desired_addresses_explicitly_refed":true,"connected":counts.connected,"announcements":counts.announcements,"written":counts.written,"completed":counts.complete,"steps":counts.steps,"pending":client.pending(),"closed":true,"full_PILS_or_Node_verified":false})
    );
    Ok(())
}
