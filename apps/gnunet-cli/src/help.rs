//! Help for the command capabilities selected at compile time.
use std::io::{self, Write};
pub(super) fn write(out: &mut impl Write) -> io::Result<()> {
    writeln!(
        out,
        "GNUnet Rust implementation (v0.29.1 compatibility, in development)"
    )?;
    #[cfg(feature = "statistics")]
    writeln!(
        out,
        "statistics get [PROGRAM -c/-L/-l] <UNIXPATH|-> [subsystem [name]]"
    )?;
    #[cfg(feature = "statistics")]
    writeln!(
        out,
        "statistics watch [PROGRAM -c/-L/-l] <UNIXPATH|-> <subsystem> <name>; - uses configured Unix/TCP endpoint; actual notifications until SIGINT/SIGTERM"
    )?;
    #[cfg(feature = "cadet")]
    writeln!(out, "cadet peers|tunnels|paths; see cadet --help")?;
    #[cfg(feature = "peerstore")]
    writeln!(out, "peerstore store|iterate|monitor; see peerstore --help")?;
    #[cfg(feature = "transport")]
    writeln!(
        out,
        "transport monitor|links [PROGRAM/options] <UNIXPATH|->; see transport --help"
    )?;
    #[cfg(feature = "vpn")]
    writeln!(out, "vpn internet|service; see vpn --help")?;
    #[cfg(feature = "regex")]
    writeln!(out, "regex search|announce; see regex --help")?;
    #[cfg(feature = "revocation")]
    writeln!(
        out,
        "revocation query|revoke|verify|mine|prepare; see revocation --help"
    )?;
    #[cfg(feature = "did")]
    writeln!(
        out,
        "did create|replace|remove|show|show-all|resolve; see did --help"
    )?;
    #[cfg(feature = "reclaim")]
    writeln!(
        out,
        "reclaim attribute-store|attribute-get|attribute-delete|attribute-list|credential-store|credential-get|credential-delete|credential-list|ticket-issue|ticket-list|ticket-revoke|ticket-consume; see reclaim --help"
    )?;
    #[cfg(feature = "namestore")]
    writeln!(
        out,
        "namestore lookup|replace|import-uri|import-zonefile|delete|batch|reverse|iterate|monitor|list-orphans|purge-orphans|purge-zone|edit-begin|edit-cancel; see namestore --help"
    )?;
    #[cfg(feature = "identity")]
    writeln!(
        out,
        "identity list|monitor|lookup|lookup-suffix|export|create|rename|delete|encrypt|decrypt; see identity --help"
    )?;
    #[cfg(feature = "fs")]
    writeln!(
        out,
        "fs extract|import|pack|cat|export|ls|publish|fetch; see fs --help"
    )?;
    #[cfg(feature = "statistics")]
    writeln!(
        out,
        "statistics set [PROGRAM -c/-L/-l] <UNIXPATH|-> <subsystem> <name> <value> [--relative] [--persistent]"
    )?;
    #[cfg(feature = "statistics")]
    writeln!(
        out,
        "GET/SET common options precede the endpoint; - selects configured Unix/TCP. GET streams without a row aggregation cap under one 10 second deadline. WATCH stays subscribed until stopped."
    )?;
    Ok(())
}
