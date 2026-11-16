//! Fixed service namespaces and foreign-marker exclusion.
use super::{Failure, failure, os};
use gnunet_native::filesystem::Directory;
use gnunet_types::Error;
use std::{ffi::OsStr, io};
/// Fixed independent production namespace. The caller cannot inject arbitrary
/// marker/file names or use another service's qualified directory by accident.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Namespace {
    /// Existing independent Rust IDENTITY snapshot format, never a C ego store.
    Identity,
    /// Independent Rust NAMESTORE authority snapshot format.
    Namestore,
    /// Independent Rust public REVOCATION certificate/fact snapshot.
    Revocation,
    /// Independent Rust REST/OIDC signer and issued grant/access state.
    Oidc,
    /// Independent Rust MESSENGER authenticated history and metadata.
    Messenger,
    /// Independent Rust HOSTLIST learned public URL/quality history.
    Hostlist,
    /// Independent Rust TRANSPORT public generation timestamp highwater.
    Transport,
    /// Independent Rust TRANSPORT public DV LEARN and BOX sender watermarks.
    TransportDv,
    /// Independent TCP authenticated replay floors, distinct from T1/DV state.
    TransportTcp,
    /// GNS publication expiration/nonce highwaters; no records or secret keys.
    GnsPublication,
}
impl Namespace {
    pub(super) const fn marker(self) -> &'static [u8] {
        match self {
            Self::Identity => b"GNUNET-RUST-IDENTITY-STORE\nversion=1\n",
            Self::Namestore => b"GNUNET-RUST-NAMESTORE-SNAPSHOT\nversion=1\n",
            Self::Revocation => b"GNUNET-RUST-REVOCATION-SNAPSHOT\nversion=1\n",
            Self::Oidc => b"GNUNET-RUST-REST-OIDC-SNAPSHOT\nversion=1\n",
            Self::Messenger => b"GNUNET-RUST-MESSENGER-SNAPSHOT\nversion=1\n",
            Self::Hostlist => b"GNUNET-RUST-HOSTLIST-SNAPSHOT\nversion=1\n",
            Self::Transport => b"GNUNET-RUST-TRANSPORT-MONOTIME\nversion=1\n",
            Self::TransportDv => b"GNUNET-RUST-TRANSPORT-DV-PUBLIC\nversion=1\n",
            Self::TransportTcp => b"GNUNET-RUST-TCP-REPLAY-LEDGER\nversion=2\n",
            Self::GnsPublication => b"GNUNET-RUST-GNS-PUBLICATION-NONCES\nversion=1\n",
        }
    }
    pub(super) const fn mark(self) -> &'static str {
        match self {
            Self::Identity => ".identity-rust-store",
            Self::Namestore => ".namestore-rust-store",
            Self::Revocation => ".revocation-rust-store",
            Self::Oidc => ".rest-oidc-rust-store",
            Self::Messenger => ".messenger-rust-store",
            Self::Hostlist => ".hostlist-rust-store",
            Self::Transport => ".transport-rust-monotime-store",
            Self::TransportDv => ".transport-rust-dv-store",
            Self::TransportTcp => ".tcp-rust-replay-store",
            Self::GnsPublication => ".gns-publication-rust-store",
        }
    }
    pub(super) const fn image(self) -> &'static str {
        match self {
            Self::Identity => "identity.snapshot",
            Self::Namestore => "namestore.snapshot",
            Self::Revocation => "revocation.snapshot",
            Self::Oidc => "rest-oidc.snapshot",
            Self::Messenger => "messenger.snapshot",
            Self::Hostlist => "hostlist.snapshot",
            Self::Transport => "transport-monotime.snapshot",
            Self::TransportDv => "transport-dv.snapshot",
            Self::TransportTcp => "tcp-replay.snapshot",
            Self::GnsPublication => "gns-publication.snapshot",
        }
    }
    pub(super) const fn lock(self) -> &'static str {
        match self {
            Self::Identity => ".identity-rust.lock",
            Self::Namestore => ".namestore-rust.lock",
            Self::Revocation => ".revocation-rust.lock",
            Self::Oidc => ".rest-oidc-rust.lock",
            Self::Messenger => ".messenger-rust.lock",
            Self::Hostlist => ".hostlist-rust.lock",
            Self::Transport => ".transport-rust-monotime.lock",
            Self::TransportDv => ".transport-rust-dv.lock",
            Self::TransportTcp => ".tcp-rust-replay.lock",
            Self::GnsPublication => ".gns-publication-rust.lock",
        }
    }
    pub(super) const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Identity => b"GNIDST01",
            Self::Namestore => b"GNNMST01",
            Self::Revocation => b"GNREV001",
            Self::Oidc => b"GNOIDC01",
            Self::Messenger => b"GNMSG001",
            Self::Hostlist => b"GNHOST01",
            Self::Transport => b"GNTRNS01",
            Self::TransportDv => b"GNDVST01",
            Self::TransportTcp => b"GNTCPS02",
            Self::GnsPublication => b"GNGNSP01",
        }
    }
    pub(super) const fn temporary(self) -> &'static str {
        match self {
            Self::Identity => "pending.",
            Self::Namestore => "namestore.pending.",
            Self::Revocation => "revocation.pending.",
            Self::Oidc => "rest-oidc.pending.",
            Self::Messenger => "messenger.pending.",
            Self::Hostlist => "hostlist.pending.",
            Self::Transport => "transport-monotime.pending.",
            Self::TransportDv => "transport-dv.pending.",
            Self::TransportTcp => "tcp-replay.pending.",
            Self::GnsPublication => "gns-publication.pending.",
        }
    }
    pub(crate) const fn thread_name(self) -> &'static str {
        match self {
            Self::Identity => "gnunet-identity-store",
            Self::Namestore => "gnunet-namestore-store",
            Self::Revocation => "gnunet-revocation-store",
            Self::Oidc => "gnunet-rest-oidc-store",
            Self::Messenger => "gnunet-messenger-store",
            Self::Hostlist => "gnunet-hostlist-store",
            Self::Transport => "gnunet-transport-monotime-store",
            Self::TransportDv => "gnunet-transport-dv-store",
            Self::TransportTcp => "gnunet-tcp-replay-store",
            Self::GnsPublication => "gnunet-gns-nonce",
        }
    }
}
pub(super) fn guard(directory: &Directory, namespace: Namespace) -> Result<(), Failure> {
    for other in [
        Namespace::Identity,
        Namespace::Namestore,
        Namespace::Revocation,
        Namespace::Oidc,
        Namespace::Messenger,
        Namespace::Hostlist,
        Namespace::Transport,
        Namespace::TransportDv,
        Namespace::TransportTcp,
        Namespace::GnsPublication,
    ] {
        if other == namespace {
            continue;
        }
        match directory.entry_info(OsStr::new(other.mark())) {
            Ok(_) => return Err(failure("foreign-namespace", Error::Authentication, None)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(os("namespace-marker-probe", e)),
        }
    }
    Ok(())
}
