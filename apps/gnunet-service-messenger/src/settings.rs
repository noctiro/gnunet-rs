//! Official SERVICE routing settings and explicit finite Rust resource policy.
use crate::Failure;
use gnunet_config::{Configuration, ProcessEnvironment};
use gnunet_messenger_service_host::{core, history, layout, server};
use gnunet_service_runtime::{
    credentials::UnixAccess,
    service::{ServiceOptions, ShutdownMode},
    service_options,
};
use std::{path::PathBuf, time::Duration};

const RUST: &[u8] = b"messenger-rust";
fn number(c: &Configuration, key: &[u8], d: usize) -> Result<usize, Failure> {
    Ok(c.get(RUST, key)
        .map(|_| c.get_number(RUST, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(d))
}
fn size(c: &Configuration, key: &[u8], d: usize) -> Result<usize, Failure> {
    Ok(c.get(RUST, key)
        .map(|_| c.get_size(RUST, key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(d))
}
fn time(c: &Configuration, key: &[u8], d: u64) -> Result<Duration, Failure> {
    let t = c
        .get(RUST, key)
        .map(|_| c.get_time(RUST, key))
        .transpose()?
        .unwrap_or(d);
    if t == 0
        || t == u64::MAX
        || std::time::Instant::now()
            .checked_add(Duration::from_micros(t))
            .is_none()
    {
        return Err("MESSENGER time budgets must be finite/nonzero".into());
    }
    Ok(Duration::from_micros(t))
}
fn yes(c: &Configuration, key: &[u8], d: bool) -> Result<bool, Failure> {
    Ok(c.get(b"messenger", key)
        .map(|_| c.get_yesno(b"messenger", key))
        .transpose()?
        .unwrap_or(d))
}
pub(super) struct Settings {
    pub core: core::Limits,
    pub native: server::Limits,
    pub options: ServiceOptions,
    pub unix: UnixAccess,
    pub resolver: gnunet_resolver_broker::Limits,
    pub grace: Duration,
    pub startup: Duration,
    pub history_directory: Option<PathBuf>,
    pub history: history::Limits,
    pub layouts: layout::Policy,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let profile = core::wire::profile::Profile::NATIVE_255;
        let peer_profile = match c.get(RUST, b"PEER_ENDIAN") {
            None => profile,
            Some(v) if v.eq_ignore_ascii_case(b"little") => {
                core::wire::profile::Profile::LITTLE_255
            }
            Some(v) if v.eq_ignore_ascii_case(b"big") => core::wire::profile::Profile::BIG_255,
            Some(_) => return Err("PEER_ENDIAN must be little or big".into()),
        };
        let native = server::Limits {
            pils_profile: gnunet_pils::Profile::configured(
                c.get(b"PILS", b"PROFILE"),
                c.get(RUST, b"PILS_PROFILE"),
            )?,
            clients: number(c, b"MAX_CLIENTS", 16)?,
            rooms: number(c, b"MAX_ROOMS", 4)?,
            client_rooms: number(c, b"ROOMS_PER_CLIENT", 4)?,
            tunnels: number(c, b"MAX_TUNNELS", 16)?,
            deliveries: number(c, b"DELIVERY_RELATIONS", 512)?,
            signatures: number(c, b"SIGNATURE_JOBS", 16)?,
            controls: number(c, b"CONTROLS_PER_CLIENT", 8)?,
            frame_bytes: 65535,
            io_slice_bytes: size(c, b"IO_SLICE_BYTES", 65535)?,
            input_lifetime: time(c, b"INPUT_LIFETIME", 30_000_000)?,
            operation_lifetime: time(c, b"OPERATION_LIFETIME", 60_000_000)?,
            retirement_grace: time(c, b"RETIREMENT_GRACE", 5_000_000)?,
            profile,
            peer_profile,
            group_keys: yes(c, b"MESSENGER_GROUP_KEYS", true)?,
            auto_routing: yes(c, b"MESSENGER_AUTO_ROUTING", true)?,
            auto_connecting: yes(c, b"MESSENGER_AUTO_CONNECTING", true)?,
            local_request: yes(c, b"MESSENGER_LOCAL_REQUEST", false)?,
            min_routers: c
                .get(b"messenger", b"MESSENGER_MIN_ROUTERS")
                .map(|_| c.get_number(b"messenger", b"MESSENGER_MIN_ROUTERS"))
                .transpose()?
                .map(usize::try_from)
                .transpose()?
                .unwrap_or(2),
        };
        let core = core::Limits {
            own_signers: number(c, b"OWN_SIGNER_IDENTITIES", 256)?,
            rooms: native.rooms,
            contacts: number(c, b"CONTACTS", 256)?,
            sources_per_room: native
                .clients
                .checked_add(native.tunnels)
                .and_then(|v| v.checked_add(1))
                .ok_or("source capacity overflow")?,
            sessions_per_room: number(c, b"SESSIONS_PER_ROOM", 64)?,
            messages_per_room: number(c, b"MESSAGES_PER_ROOM", 128)?,
            epochs_per_room: number(c, b"EPOCHS_PER_ROOM", 64)?,
            groups_per_epoch: number(c, b"GROUPS_PER_EPOCH", 8)?,
            subscriptions_per_room: number(c, b"SUBSCRIPTIONS_PER_ROOM", 64)?,
            operations_per_room: native.signatures,
            events: 256,
            missing_per_room: number(c, b"MISSING_PER_ROOM", 64)?,
            nonce_per_epoch: number(c, b"NONCES_PER_EPOCH", 128)?,
            frame_bytes: 65524,
            name_bytes: 4096,
            total_bytes: size(c, b"RETAINED_BYTES", 8 * 1024 * 1024)?,
            work_per_turn: number(c, b"WORK_PER_TURN", 32)?,
        };
        core.validate()?;
        if native.clients == 0
            || native.clients > 256
            || native.rooms == 0
            || native.rooms > 64
            || native.client_rooms == 0
            || native.client_rooms > native.rooms
            || native.tunnels == 0
            || native.tunnels > 256
            || native.deliveries < native.clients + native.tunnels
            || native.deliveries > 65536
            || native.signatures == 0
            || native.signatures > 16
            || native.controls < 2
            || native.controls > 256
            || native.io_slice_bytes == 0
            || native.min_routers > native.tunnels
            || core.messages_per_room > 65536
            || core.total_bytes > 512 * 1024 * 1024
            || core.own_signers > 65536
        {
            return Err("invalid MESSENGER bounded resource policy".into());
        }
        let volatile = c
            .get(RUST, b"VOLATILE")
            .map(|_| c.get_yesno(RUST, b"VOLATILE"))
            .transpose()?
            .unwrap_or(false);
        let history_directory = if volatile {
            None
        } else {
            let path = if c.get(RUST, b"HISTORY_DIRECTORY").is_some() {
                c.get_filename(RUST, b"HISTORY_DIRECTORY", &ProcessEnvironment)?
            } else if c.get(b"messenger", b"MESSENGER_DIR").is_some() {
                // The C directory is never opened or migrated. A distinct sibling
                // namespace is selected from the public configured path only.
                let mut path = c
                    .get_filename(b"messenger", b"MESSENGER_DIR", &ProcessEnvironment)?
                    .into_os_string();
                path.push(".rust-history-v1");
                PathBuf::from(path)
            } else {
                let raw = b"${GNUNET_DATA_HOME}/messenger-rust-v1";
                let value = c.expand_dollar(raw, &ProcessEnvironment)?;
                if value == raw {
                    return Err("set HISTORY_DIRECTORY, MESSENGER_DIR or GNUNET_DATA_HOME; VOLATILE is an explicit opt-out".into());
                }
                c.expand_filename(&value, &ProcessEnvironment)?
            };
            if !path.is_absolute() {
                return Err("MESSENGER history directory must be absolute".into());
            }
            Some(path)
        };
        let history = history::Limits {
            image_bytes: size(c, b"HISTORY_IMAGE_BYTES", 16 * 1024 * 1024)?,
            batch_events: u64::try_from(number(c, b"HISTORY_BATCH_EVENTS", 32)?)?,
            batch_delay: time(c, b"HISTORY_BATCH_DELAY", 16_000)?,
        };
        if history.image_bytes == 0
            || history.image_bytes > 64 * 1024 * 1024
            || history.batch_events == 0
            || !volatile && history.image_bytes < core.total_bytes
        {
            return Err("invalid bounded history image/batch policy".into());
        }
        let maximum = number(c, b"LAYOUT_RULES", 64)?;
        if maximum == 0 || maximum > 4096 {
            return Err("LAYOUT_RULES must be in 1..=4096".into());
        }
        let common_file = match c.get(RUST, b"COMMON_FILE_NAME_BYTES") {
            Some(v) if v.eq_ignore_ascii_case(b"reject") => None,
            _ => Some(core::wire::profile::Profile {
                endian: profile.endian,
                file_name_bytes: number(c, b"COMMON_FILE_NAME_BYTES", 255)?,
            }),
        };
        let mut layouts = layout::Policy::new(maximum, peer_profile, profile, common_file)?;
        producer_rules(c, &mut layouts, maximum)?;
        Ok(Self {
            core,
            native,
            options: service_options(c, b"messenger", ShutdownMode::Immediate)?,
            unix: UnixAccess {
                match_uid: yes(c, b"UNIX_MATCH_UID", true)?,
                match_gid: yes(c, b"UNIX_MATCH_GID", false)?,
            },
            resolver: gnunet_resolver_broker::Limits {
                max_frame_bytes: 65535,
                io_chunk_bytes: native.io_slice_bytes,
                max_queued_frames: 4,
            },
            grace: time(c, b"SHUTDOWN_GRACE", 10_000_000)?,
            startup: time(c, b"PILS_STARTUP_TIMEOUT", 30_000_000)?,
            history_directory,
            history,
            layouts,
        })
    }
}

// Explicit local configuration grammar, never an on-wire profile extension.
// Entries are whitespace-separated; no file is read and no connection ABI is guessed.
fn hex<const N: usize>(value: &str) -> Result<[u8; N], Failure> {
    if value.len() != N.checked_mul(2).ok_or("hex length overflow")? {
        return Err("incorrect public selector hex length".into());
    }
    let mut output = [0; N];
    fn nibble(x: u8) -> Result<u8, Failure> {
        match x {
            b'0'..=b'9' => Ok(x - b'0'),
            b'a'..=b'f' => Ok(x - b'a' + 10),
            b'A'..=b'F' => Ok(x - b'A' + 10),
            _ => Err("invalid public selector hex".into()),
        }
    }
    for (out, pair) in output.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        *out = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(output)
}
fn explicit_profile(order: &str, width: &str) -> Result<core::wire::profile::Profile, Failure> {
    use core::wire::profile::{Endian, Profile};
    let endian = match order {
        "little" => Endian::Little,
        "big" => Endian::Big,
        _ => return Err("layout order must be little/big".into()),
    };
    let profile = Profile {
        endian,
        file_name_bytes: width.parse()?,
    };
    profile.validate()?;
    Ok(profile)
}
fn producer_rules(
    c: &Configuration,
    policy: &mut layout::Policy,
    maximum: usize,
) -> Result<(), Failure> {
    fn entries<'a>(c: &'a Configuration, key: &[u8]) -> Result<&'a str, Failure> {
        let raw = c.get(RUST, key).unwrap_or(b"");
        if raw.len() > 1024 * 1024 {
            return Err("layout configuration exceeds 1MiB".into());
        }
        Ok(std::str::from_utf8(raw)?)
    }
    for (n, word) in entries(c, b"RELAY_LAYOUTS")?
        .split_ascii_whitespace()
        .enumerate()
    {
        if n >= maximum {
            return Err("too many relay layouts".into());
        }
        // peerhex/port-order/name-max/incoming-order/outgoing-order
        let mut x = word.split('/');
        let peer = hex(x.next().ok_or("relay peer missing")?)?;
        let port = explicit_profile(
            x.next().ok_or("port order missing")?,
            x.next().ok_or("name width missing")?,
        )?;
        let incoming = explicit_profile(x.next().ok_or("incoming order missing")?, "255")?;
        let outgoing = explicit_profile(x.next().ok_or("outgoing order missing")?, "255")?;
        if x.next().is_some() {
            return Err("extra relay layout field".into());
        }
        policy.insert_transport(
            peer,
            layout::Transport {
                port,
                incoming_padding: incoming,
                outgoing_padding: outgoing,
            },
        )?;
    }
    for (n, word) in entries(c, b"ROOM_LAYOUTS")?
        .split_ascii_whitespace()
        .enumerate()
    {
        if n >= maximum {
            return Err("too many room layouts".into());
        }
        let mut x = word.split('/');
        let key = hex(x.next().ok_or("room key missing")?)?;
        let profile = explicit_profile(
            x.next().ok_or("room order missing")?,
            x.next().ok_or("room name width missing")?,
        )?;
        if x.next().is_some() {
            return Err("extra room layout field".into());
        }
        policy.insert_room(key, profile)?;
    }
    for (n, word) in entries(c, b"PRODUCER_LAYOUTS")?
        .split_ascii_whitespace()
        .enumerate()
    {
        if n >= maximum {
            return Err("too many producer layouts".into());
        }
        let mut x = word.split('/');
        let kind = x.next().ok_or("producer kind missing")?;
        let selector = match kind {
            "member" => layout::Selector::Member(hex(x.next().ok_or("member public missing")?)?),
            "peer" => layout::Selector::Peer(hex(x.next().ok_or("peer public missing")?)?),
            "message-member" => layout::Selector::Message {
                room: hex(x.next().ok_or("message room missing")?)?,
                hash: hex(x.next().ok_or("message hash missing")?)?,
                signer: core::OriginalSigner::Member(hex(x
                    .next()
                    .ok_or("message signer missing")?)?),
            },
            "message-peer" => layout::Selector::Message {
                room: hex(x.next().ok_or("message room missing")?)?,
                hash: hex(x.next().ok_or("message hash missing")?)?,
                signer: core::OriginalSigner::Peer(hex(x
                    .next()
                    .ok_or("message signer missing")?)?),
            },
            _ => return Err("unknown producer selector".into()),
        };
        let profile = explicit_profile(
            x.next().ok_or("producer order missing")?,
            x.next().ok_or("producer name width missing")?,
        )?;
        if x.next().is_some() {
            return Err("extra producer layout field".into());
        }
        policy.insert(selector, core::BodyLayout::Explicit(profile))?;
    }
    Ok(())
}

#[cfg(test)]
mod profile_tests {
    use super::*;
    use gnunet_pils::Profile;

    fn config() -> Result<Configuration, Failure> {
        let mut config = Configuration::default();
        config.set_value(RUST, b"VOLATILE", Some(b"YES"))?;
        Ok(config)
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Compare independently selected PILS semantics and the unchanged Messenger producer grammar"
    )]
    fn normal_pils_profile_selects_crypto_without_changing_producer_layout() -> Result<(), Failure>
    {
        let mut config = config()?;
        let normal = Settings::read(&config)?;
        assert_eq!(normal.native.pils_profile, Profile::Reference029);
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        let conditional = Settings::read(&config)?;
        assert_eq!(
            conditional.native.pils_profile,
            Profile::ReferenceDeterministic
        );
        assert_eq!(conditional.native.profile, normal.native.profile);
        assert_eq!(conditional.native.peer_profile, normal.native.peer_profile);
        config.set_value(RUST, b"PILS_PROFILE", Some(b"deterministic"))?;
        assert_eq!(
            Settings::read(&config)?.native.pils_profile,
            Profile::ReferenceDeterministic
        );
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Exact typed selection refusals must not silently start another producer profile"
    )]
    fn normal_pils_profile_refuses_conflicts_and_unknown_before_startup() -> Result<(), Failure> {
        let mut config = config()?;
        config.set_value(b"PILS", b"PROFILE", Some(b"deterministic"))?;
        config.set_value(RUST, b"PILS_PROFILE", Some(b"reference029"))?;
        let conflict = Settings::read(&config)
            .err()
            .ok_or("conflicting PILS choice accepted")?;
        assert_eq!(
            conflict.downcast_ref::<gnunet_types::Error>(),
            Some(&gnunet_types::Error::Conflict)
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"unknown"))?;
        config.set_value(RUST, b"PILS_PROFILE", Some(b"deterministic"))?;
        let unknown = Settings::read(&config)
            .err()
            .ok_or("unknown node choice accepted")?;
        assert_eq!(
            unknown.downcast_ref::<gnunet_types::Error>(),
            Some(&gnunet_types::Error::InvalidInput)
        );
        config.set_value(b"PILS", b"PROFILE", Some(b"reference029"))?;
        config.set_value(RUST, b"PILS_PROFILE", Some(b"unknown"))?;
        let unknown = Settings::read(&config)
            .err()
            .ok_or("unknown local choice accepted")?;
        assert_eq!(
            unknown.downcast_ref::<gnunet_types::Error>(),
            Some(&gnunet_types::Error::InvalidInput)
        );
        config.set_value(RUST, b"PILS_PROFILE", Some(b"reference-0.29.1"))?;
        assert_eq!(
            Settings::read(&config)?.native.pils_profile,
            Profile::Reference029
        );
        Ok(())
    }
}
