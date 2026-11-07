//! Test-only public-client actor for one controlled official-C NAMECACHE MQ.
//! Static published ciphertext/query only; no key input or decryption.
#![cfg(unix)]
use gnunet_namecache_client_host::{
    Cancellation, Client, Completion, EndpointSource, Instance, Limits, LocalReason, Operation,
    Outcome, Progress, Submission,
    clock::{RuntimeClock, SystemClock},
};
use gnunet_types::Error as Fault;
use std::{
    error::Error,
    io::{self, Write},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::time::Instant;
type Failure = Box<dyn Error>;
const CIPHER: &[u8] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/edkey_ascii-block.bin");
const QUERY: &[u8; 64] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/edkey_ascii-query.bin");
async fn completion<'id>(
    client: &mut Client<'id>,
    operation: Operation<'id>,
    hard: Instant,
) -> Result<Completion<'id>, Failure> {
    loop {
        match client.drive(Some(hard)).await? {
            Progress::Completed(done) if done.operation == operation => return Ok(done),
            Progress::Written { request_id, .. } => {
                writeln!(
                    io::stdout().lock(),
                    "WRITTEN rid={request_id} local-whole-write-only"
                )?;
            }
            Progress::Lost { cause, .. } => {
                return Err(format!("original NAMECACHE source lost: {cause:?}").into());
            }
            Progress::ConnectRetry { error, .. } => return Err(error.into()),
            Progress::Unavailable(error) => return Err(error.into()),
            Progress::WaitDeadline | Progress::Closed => return Err(Fault::Deadline.into()),
            Progress::Completed(_) => return Err(Fault::StaleGeneration.into()),
            _ => {}
        }
    }
}
fn until(client: &Client<'_>, hard: Instant) -> Result<u64, Failure> {
    if Instant::now() >= hard {
        return Err(Fault::Deadline.into());
    }
    Ok(client
        .clock()
        .sample()?
        .now
        .as_micros()
        .checked_add(4_000_000)
        .ok_or(Fault::Overflow)?)
}
async fn run(client: &mut Client<'_>, mode: &str, hard: Instant) -> Result<(), Failure> {
    if mode == "cycle" {
        let operation = client.lookup(QUERY, until(client, hard)?)?;
        if client.cancel(operation)? != Cancellation::Unsent {
            return Err(Fault::Stale.into());
        }
        if !matches!(
            completion(client, operation, hard).await?.outcome,
            Outcome::Local {
                reason: LocalReason::Cancelled,
                submission: Submission::Unsent
            }
        ) {
            return Err(Fault::Malformed.into());
        }
    }
    if mode != "miss" {
        let operation = client.cache(CIPHER, until(client, hard)?)?;
        if !matches!(
            completion(client, operation, hard).await?.outcome,
            Outcome::Cache(1)
        ) {
            return Err(Fault::Malformed.into());
        }
        if mode == "seed" {
            return Ok(());
        }
        let operation = client.lookup(QUERY, until(client, hard)?)?;
        let Outcome::Lookup(Some(block)) = completion(client, operation, hard).await?.outcome
        else {
            return Err(Fault::NotFound.into());
        };
        if block.bytes() != CIPHER
            || block.query() != QUERY
            || block.expiration().as_micros() != 17_999_736_901_000_000
        {
            return Err(Fault::Authentication.into());
        }
        let operation = client.delete(QUERY, until(client, hard)?)?;
        if !matches!(
            completion(client, operation, hard).await?.outcome,
            Outcome::Delete(1)
        ) {
            return Err(Fault::Malformed.into());
        }
    }
    let operation = client.lookup(QUERY, until(client, hard)?)?;
    if !matches!(
        completion(client, operation, hard).await?.outcome,
        Outcome::Lookup(None)
    ) {
        return Err(Fault::Malformed.into());
    }
    if mode == "cycle" {
        let operation = client.delete(QUERY, until(client, hard)?)?;
        if !matches!(
            completion(client, operation, hard).await?.outcome,
            Outcome::Delete(0)
        ) {
            return Err(Fault::Malformed.into());
        }
    }
    Ok(())
}
fn main() -> Result<(), Failure> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() != 2 {
        return Err("usage: official_namecache <controlled-unix-path> <cycle|seed|miss>".into());
    }
    let mode = args[1].to_str().ok_or(Fault::InvalidInput)?;
    if !matches!(mode, "cycle" | "seed" | "miss") {
        return Err(Fault::InvalidInput.into());
    }
    let path = PathBuf::from(&args[0]);
    if !path.is_absolute() {
        return Err(Fault::InvalidInput.into());
    }
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let instance = Instance::new();
            let clock: Arc<dyn RuntimeClock> = Arc::new(SystemClock);
            let mut client = Client::new(
                &instance,
                EndpointSource::unix_with_clock(path, clock),
                Limits {
                    reconnect: false,
                    operations: 8,
                    retirement_grace: Duration::from_secs(1),
                    ..Limits::default()
                },
            )?;
            let hard = Instant::now()
                .checked_add(Duration::from_secs(8))
                .ok_or(Fault::Overflow)?;
            let result = run(&mut client, mode, hard).await;
            let retired = client.close();
            writeln!(io::stdout().lock(), "CLOSED original={retired:?}")?;
            result?;
            writeln!(
                io::stdout().lock(),
                "PASS rust-namecache-client mode={mode}"
            )?;
            io::stdout().lock().flush()?;
            Ok(())
        })
}
