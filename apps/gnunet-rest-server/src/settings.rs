use crate::Failure;
use gnunet_config::Configuration;
use gnunet_rest_host::Limits;
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::time::Duration;
#[cfg(feature = "oidc")]
use zeroize::Zeroizing;
const LOCAL: &[u8] = b"rest-rust";
fn n(c: &Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(LOCAL, key)
        .map(|_| c.get_number(LOCAL, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn duration(c: &Configuration, key: &[u8], default: u64) -> Result<Duration, Failure> {
    let us = c
        .get(LOCAL, key)
        .map(|_| c.get_time(LOCAL, key))
        .transpose()?
        .unwrap_or(default);
    if us == 0
        || us == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(us))
            .is_none()
    {
        return Err("REST deadlines must be finite and representable".into());
    }
    Ok(Duration::from_micros(us))
}
pub(super) struct Settings {
    pub handlers: Limits,
    pub consume_profile: gnunet_rest_host::ConsumeProfile,
    pub http: gnunet_rest_host::http::Limits,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub grace: Duration,
    pub resolver: gnunet_resolver_broker::Limits,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let mut handlers = Limits::default();
        handlers.bytes = n(c, b"MAX_BODY_BYTES", handlers.bytes)?;
        handlers.output_bytes = n(c, b"MAX_OUTPUT_BYTES", handlers.output_bytes)?;
        handlers.text_bytes = n(c, b"MAX_RECORD_TEXT_BYTES", handlers.text_bytes)?;
        handlers.items = n(c, b"MAX_ITEMS", handlers.items)?;
        handlers.json.bytes = handlers.bytes;
        handlers.json.nodes = n(c, b"JSON_NODES", handlers.json.nodes)?;
        handlers.json.work = n(c, b"JSON_WORK", handlers.json.work)?;
        handlers.lifetime = duration(c, b"REQUEST_LIFETIME", 30_000_000)?;
        let mut http = gnunet_rest_host::http::Limits::default();
        http.clients = n(c, b"MAX_CLIENTS", http.clients)?;
        http.io_bytes = n(c, b"IO_SLICE_BYTES", http.io_bytes)?;
        http.framing.body_bytes = handlers.bytes;
        http.framing.wire_bytes = n(c, b"MAX_HTTP_WIRE_BYTES", http.framing.wire_bytes)?;
        http.lifetime = handlers.lifetime;
        http.send_lifetime = duration(c, b"OUTPUT_LIFETIME", 5_000_000)?;
        if http.clients > 64
            || handlers.bytes > 65535
            || handlers.output_bytes > 1_048_576
            || handlers.text_bytes > 262140
            || handlers.text_bytes == 0
            || handlers.items > 1024
            || handlers.json.nodes > 8192
            || handlers.json.work > 16_000_000
            || http.framing.wire_bytes > 262144
            || http.io_bytes > 65535
            || handlers.bytes == 0
            || handlers.output_bytes == 0
            || handlers.items == 0
            || handlers.json.nodes == 0
            || handlers.json.work == 0
        {
            return Err("REST resource bounds invalid".into());
        }
        let yes = |key: &[u8]| -> Result<bool, Failure> {
            Ok(c.get(b"rest", key)
                .map(|_| c.get_yesno(b"rest", key))
                .transpose()?
                .unwrap_or(false))
        };
        Ok(Self {
            handlers,
            // The source producer profile applies to every RECLAIM consumer,
            // including builds where the optional OpenID provider is disabled.
            consume_profile: match c
                .get(LOCAL, b"OIDC_CONSUME_STATUS_PROFILE")
                .unwrap_or(b"canonical")
            {
                b"canonical" => gnunet_rest_host::ConsumeProfile::Canonical,
                b"c-native-little" => gnunet_rest_host::ConsumeProfile::CNativeLittle,
                _ => return Err("unknown RECLAIM consume status profile".into()),
            },
            http,
            options: service_options(c, b"rest", ShutdownMode::Soft)?,
            unix: UnixAccess {
                match_uid: yes(b"UNIX_MATCH_UID")?,
                match_gid: yes(b"UNIX_MATCH_GID")?,
            },
            grace: duration(c, b"SHUTDOWN_GRACE", 5_000_000)?,
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: http.io_bytes,
                max_queued_frames: 8,
            },
        })
    }
}
pub(super) fn listener_config(c: &Configuration, v6: bool) -> Result<Configuration, Failure> {
    let mut output = c.duplicate()?;
    let port = c
        .get(b"rest", b"HTTP_PORT")
        .map(|_| c.get_number(b"rest", b"HTTP_PORT"))
        .transpose()?
        .unwrap_or(7776);
    if port == 0 || port > 65535 {
        return Err("REST HTTP_PORT must be1..65535".into());
    }
    output.set_number(b"rest", b"PORT", port)?;
    output.set_value(
        b"rest",
        b"BINDTO",
        Some(
            c.get(b"rest", if v6 { b"BIND_TO6" } else { b"BIND_TO" })
                .unwrap_or(if v6 { b"::1" } else { b"127.0.0.1" }),
        ),
    )?;
    output.set_value(b"rest", b"DISABLEV6", Some(if v6 { b"NO" } else { b"YES" }))?;
    Ok(output)
}

/// Exact active C CONFIG output selection, independent of PROGRAM -c input.
/// Caller may explicitly choose a private Rust output path in rest-rust.
pub(super) fn configuration_target(c: &Configuration) -> Result<std::path::PathBuf, Failure> {
    use gnunet_config::Environment;
    if c.get(LOCAL, b"CONFIG_OUTPUT").is_some() {
        return Ok(c.get_filename(LOCAL, b"CONFIG_OUTPUT", &gnunet_config::ProcessEnvironment)?);
    }
    let raw = if let Some(mut xdg) = gnunet_config::ProcessEnvironment.variable(b"XDG_CONFIG_HOME")
    {
        xdg.push(b'/');
        xdg.extend_from_slice(&c.project_data().config_file);
        xdg
    } else {
        c.project_data().user_config_file.clone()
    };
    Ok(c.expand_filename(&raw, &gnunet_config::ProcessEnvironment)?)
}

#[cfg(feature = "oidc")]
pub(super) struct Oidc {
    pub provider: gnunet_rest_host::oidc::Provider,
    pub driver: gnunet_rest_host::oidc::persistence::Driver,
}
#[cfg(feature = "oidc")]
pub(super) async fn oidc(
    c: &Configuration,
    clock: std::sync::Arc<dyn gnunet_service_runtime::clock::RuntimeClock>,
) -> Result<Option<Oidc>, Failure> {
    if !oidc_enabled(c)? {
        return Ok(None);
    }
    use gnunet_rest_host::oidc::{
        Provider,
        persistence::{KeySource, Options},
    };
    let section = b"reclaim-rest-plugin";
    let origin = c
        .get(LOCAL, b"OIDC_ORIGIN")
        .ok_or("OIDC requires explicit OIDC_ORIGIN")?;
    let login = c
        .get(section, b"address")
        .ok_or("OIDC requires the actual configured login UI address")?;
    let signer = match c
        .get(section, b"oidc_json_web_algorithm")
        .unwrap_or(b"RS256")
    {
        b"RS256" => KeySource::Rs256 {
            bits: 2048,
            limits: Default::default(),
        },
        b"HS512" => {
            let secret = c
                .get(section, b"jwt_secret")
                .ok_or("HS512 requires explicit jwt_secret")?;
            let mut owned = Vec::new();
            owned.try_reserve_exact(secret.len())?;
            owned.extend_from_slice(secret);
            KeySource::Hs512 {
                secret: Zeroizing::new(owned),
                limits: Default::default(),
            }
        }
        _ => return Err("OIDC signing algorithm must be exactly RS256 or HS512".into()),
    };
    let mut limits = gnunet_rest_host::oidc::Limits::default();
    limits.sessions = n(c, b"OIDC_SESSIONS", limits.sessions)?;
    limits.grants = n(c, b"OIDC_GRANTS", limits.grants)?;
    limits.accesses = n(c, b"OIDC_ACCESS_TOKENS", limits.accesses)?;
    limits.bytes = n(c, b"OIDC_CACHE_BYTES", limits.bytes)?;
    limits.ttl = c
        .get(section, b"expiration_time")
        .map(|_| c.get_time(section, b"expiration_time"))
        .transpose()?
        .map(Duration::from_micros)
        .unwrap_or(limits.ttl);
    if limits.sessions > 1024
        || limits.grants > 128
        || limits.accesses > 1024
        || limits.bytes > 8_388_608
        || limits.ttl.as_secs() > 86400
    {
        return Err("OIDC resource bounds invalid".into());
    }
    if c.get(LOCAL, b"OIDC_STATE_DIRECTORY").is_none() {
        return Err("OIDC requires explicit private Rust OIDC_STATE_DIRECTORY".into());
    }
    let directory = c.get_filename(
        LOCAL,
        b"OIDC_STATE_DIRECTORY",
        &gnunet_config::ProcessEnvironment,
    )?;
    let default_snapshot = limits
        .bytes
        .checked_add(65536)
        .and_then(|n| {
            limits
                .grants
                .checked_add(limits.accesses)
                .and_then(|rows| rows.checked_mul(128))
                .and_then(|rows| n.checked_add(rows))
        })
        .ok_or("OIDC snapshot bound overflow")?;
    let snapshot_bytes = n(c, b"OIDC_SNAPSHOT_BYTES", default_snapshot)?;
    if snapshot_bytes > 64 * 1024 * 1024 {
        return Err("OIDC snapshot bound exceeds private store maximum".into());
    }
    let (provider, driver) = Provider::persistent(
        clock,
        Options {
            directory,
            signer,
            origin,
            login_ui: login,
            client_secret: c.get(section, b"OIDC_CLIENT_HMAC_SECRET"),
            limits,
            snapshot_bytes,
        },
    )
    .await?;
    Ok(Some(Oidc { provider, driver }))
}
pub(super) fn oidc_enabled(c: &Configuration) -> Result<bool, Failure> {
    Ok(c.get(LOCAL, b"OIDC_ENABLED")
        .map(|_| c.get_yesno(LOCAL, b"OIDC_ENABLED"))
        .transpose()?
        .unwrap_or(false))
}
