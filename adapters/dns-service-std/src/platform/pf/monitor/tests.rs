//! Private ordinary subprocess fixtures; no PF, privilege or device operation.
use super::*;
use crate::platform::pf::command::Runner;
use std::{
    fs::{self, DirBuilder, OpenOptions},
    future::{Future, poll_fn},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    task::Poll,
    time::{SystemTime, UNIX_EPOCH},
};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

fn fixture() -> io::Result<(Directory, Controls, String)> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(io::Error::other)?
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "gnunet-pf-observation-{}-{stamp}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    DirBuilder::new().mode(0o700).create(&directory)?;
    let directory = Directory(directory);
    let lease = directory.0.join("lease");
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&lease)?;
    lock.try_lock().map_err(io::Error::other)?;
    let native = gnunet_native::interfaces::snapshot(Default::default())?;
    let interface = native
        .first()
        .ok_or_else(|| io::Error::other("private observation fixture needs a local address"))?;
    let interface = String::from_utf8(interface.name.clone()).map_err(io::Error::other)?;
    let mut names = native
        .iter()
        .map(|row| row.name.clone())
        .collect::<Vec<_>>();
    names.sort_unstable();
    names.dedup();
    let mut listing = Vec::new();
    for name in names {
        listing.extend_from_slice(&name);
        listing.push(b'\n');
    }
    let label = "gnunet-rs-dns-private-fixture".to_owned();
    let canonical = rules::render(
        &interface,
        std::net::Ipv4Addr::LOCALHOST,
        std::net::Ipv6Addr::LOCALHOST,
        nix::unistd::getegid().as_raw(),
        &label,
    )?
    .into_bytes();
    for (name, bytes) in [
        ("info", b"Status: Enabled for 0 days\n".as_slice()),
        ("root", b"anchor \"gnunet-rs/dns\" all\n".as_slice()),
        ("rules", canonical.as_slice()),
        ("children", b"".as_slice()),
        ("interfaces", listing.as_slice()),
    ] {
        fs::write(directory.0.join(name), bytes)?;
    }
    let program = directory.0.join("query");
    fs::write(
        &program,
        br##"#!/bin/sh
directory=${0%/*}
printf '%s\n' "$*" >> "$directory/queries"
if [ -f "$directory/block" ]; then exec /bin/sleep 10; fi
case "$*" in
  '-s info') exec /bin/cat "$directory/info" ;;
  '-s rules') exec /bin/cat "$directory/root" ;;
  '-a gnunet-rs/dns -s rules') exec /bin/cat "$directory/rules" ;;
  '-a gnunet-rs/dns -s Anchors') exec /bin/cat "$directory/children" ;;
  '-v -s Interfaces') exec /bin/cat "$directory/interfaces" ;;
  *) exit 97 ;;
esac
"##,
    )?;
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700))?;
    let runner = Runner::leased(&lock)?;
    Ok((
        directory,
        Controls {
            lock,
            lease,
            program,
            runner,
            state: State::Installed,
            label,
            canonical,
            scope: Some(Scope::new(native)),
        },
        interface,
    ))
}

#[test]
fn disabled_or_ambiguous_status_never_admits_a_policy_observation() -> io::Result<()> {
    for status in [
        b"Status: Disabled for 0 days\n".as_slice(),
        b"Status: EnabledElsewhere\n",
        b"Status: Enabled\nStatus: Disabled\n",
        b"Debug: Enabled\n",
    ] {
        if require_enabled(status).is_ok() {
            return Err(io::Error::other("disabled or ambiguous PF status admitted"));
        }
    }
    require_enabled(b"Status: Enabled for 0 days 01:02:03 Debug: Urgent\n")
}

#[test]
fn read_only_observation_refuses_replacement_policy_and_keeps_the_original_scope() -> io::Result<()>
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (directory, mut controls, interface) = fixture()?;
            let user = nix::unistd::geteuid();
            let current = controls
                .observe(&interface, Instant::now() + ALLOWANCE)
                .await?;
            controls
                .scope
                .as_ref()
                .ok_or_else(|| io::Error::other("original observation scope lost"))?
                .require_same(&current)?;
            fs::write(directory.0.join("rules"), b"pass all\n")?;
            if controls
                .observe(&interface, Instant::now() + ALLOWANCE)
                .await
                .is_ok()
            {
                return Err(io::Error::other("foreign policy was adopted"));
            }
            if !controls.runner.idle() || nix::unistd::geteuid() != user {
                return Err(io::Error::other(
                    "observation changed the parent or lost its child",
                ));
            }
            if fs::read(directory.0.join("rules"))? != b"pass all\n" {
                return Err(io::Error::other(
                    "read-only observation rewrote foreign policy",
                ));
            }
            // Expiry before the first query must not admit another child.
            let before = fs::read(directory.0.join("queries"))?;
            if controls.observe(&interface, Instant::now()).await.is_ok()
                || fs::read(directory.0.join("queries"))? != before
            {
                return Err(io::Error::other("expired observation admitted native work"));
            }
            Ok(())
        })
}

#[test]
fn canceled_observation_keeps_its_original_child_for_stop_and_reap() -> io::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (directory, mut controls, interface) = fixture()?;
            fs::write(directory.0.join("block"), b"")?;
            {
                let mut waiting =
                    std::pin::pin!(controls.observe(&interface, Instant::now() + ALLOWANCE));
                poll_fn(|cx| match waiting.as_mut().poll(cx) {
                    Poll::Pending => Poll::Ready(Ok(())),
                    Poll::Ready(_) => Poll::Ready(Err(io::Error::other(
                        "observation did not retain its private pending child",
                    ))),
                })
                .await?;
            }
            if controls.runner.idle() {
                return Err(io::Error::other(
                    "canceled observation lost its original child",
                ));
            }
            if controls
                .observe(&interface, Instant::now() + ALLOWANCE)
                .await
                .is_ok()
            {
                return Err(io::Error::other(
                    "canceled observation admitted a replacement",
                ));
            }
            controls.runner.retire().await?;
            if !controls.runner.idle() {
                return Err(io::Error::other(
                    "original observation child was not reaped",
                ));
            }
            Ok(())
        })
}

#[test]
fn probe_output_failure_fences_the_caller_before_original_child_retirement() -> io::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let (directory, mut controls, interface) = fixture()?;
            fs::write(directory.0.join("info"), vec![b'x'; 32769])?;
            if controls
                .observe(&interface, Instant::now() + ALLOWANCE)
                .await
                .is_ok()
                || controls.runner.idle()
            {
                return Err(io::Error::other(
                    "probe failure did not return with its original child retained",
                ));
            }
            controls.runner.retire().await?;
            if !controls.runner.idle() {
                return Err(io::Error::other("failed probe retirement was unconfirmed"));
            }
            Ok(())
        })
}
