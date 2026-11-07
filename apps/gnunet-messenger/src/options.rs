//! Bounded official caller options; secrets never enter Debug or diagnostics.
use crate::Failure;
use gnunet_config::Configuration;
use gnunet_messenger_host::{Limits, crypto, wire::profile::Profile};
use gnunet_program_host::{
    getopt::{self, Argument, Context, Definition, Output, Spec},
    helpers::{self, Target},
};
use std::{cell::RefCell, rc::Rc, time::Duration};
use zeroize::Zeroizing;

pub(super) const INPUT_BYTES: usize = 57344;
type Bytes = Rc<RefCell<Option<Zeroizing<Vec<u8>>>>>;
pub(super) struct Selection {
    ego: Bytes,
    room: Bytes,
    door: Bytes,
    secret: Bytes,
    private: Target<i32>,
    silence: Target<i32>,
    request: Target<i32>,
    talk: Target<i32>,
    public: Target<i32>,
}
fn bytes_option(
    short: u8,
    name: &'static [u8],
    label: &'static [u8],
    description: &'static [u8],
    maximum: usize,
    target: Bytes,
) -> Definition<'static> {
    Definition::new(
        Spec {
            short,
            name,
            argument_help: Some(label),
            description: Some(description),
            argument: Argument::Required,
            mandatory: false,
            exclusive: false,
        },
        move |_: Context<'_>, _: &[u8], value: Option<&[u8]>, _: &mut Output| {
            let Some(value) = value else {
                return -1;
            };
            if value.len() > maximum || value.contains(&0) {
                return -1;
            }
            let Ok(mut slot) = target.try_borrow_mut() else {
                return -1;
            };
            let mut bytes = Zeroizing::new(Vec::new());
            if bytes.try_reserve_exact(value.len()).is_err() {
                return -1;
            }
            bytes.extend_from_slice(value);
            *slot = Some(bytes);
            1
        },
    )
}
impl Selection {
    pub(super) fn new() -> Self {
        Self {
            ego: Rc::default(),
            room: Rc::default(),
            door: Rc::default(),
            secret: Rc::default(),
            private: Target::new(0),
            silence: Target::new(0),
            request: Target::new(0),
            talk: Target::new(0),
            public: Target::new(0),
        }
    }
    pub(super) fn descriptors(&self) -> getopt::Options<'static> {
        let mut options = getopt::Options::new();
        options.add(bytes_option(
            b'd',
            b"door",
            b"PEERIDENTITY",
            b"peer identity through which to enter the room",
            52,
            self.door.clone(),
        ));
        options.add(bytes_option(
            b'e',
            b"ego",
            b"IDENTITY",
            b"existing IDENTITY ego for messaging",
            4096,
            self.ego.clone(),
        ));
        options.add(bytes_option(
            b'r',
            b"room",
            b"ROOMKEY",
            b"room name whose official hash determines the room",
            4096,
            self.room.clone(),
        ));
        options.add(bytes_option(
            b'S',
            b"secret",
            b"SECRET",
            b"Base32GNS storage secret for local keys",
            103,
            self.secret.clone(),
        ));
        options.add(helpers::flag(
            b'p',
            b"private",
            b"send separately to each current member",
            self.private.clone(),
        ));
        options.add(helpers::flag(
            b's',
            b"silence",
            b"silence received content and send only",
            self.silence.clone(),
        ));
        options.add(helpers::flag(
            b'R',
            b"request",
            b"request original predecessors and cached history",
            self.request.clone(),
        ));
        options.add(helpers::flag(
            b't',
            b"talk",
            b"read and write binary TALK data",
            self.talk.clone(),
        ));
        options.add(helpers::flag(
            b'P',
            b"public",
            b"disable room forward secrecy",
            self.public.clone(),
        ));
        options
    }
    pub(super) fn finish(self, config: &Configuration) -> Result<Settings, Failure> {
        let take = |value: Bytes| -> Result<Option<Zeroizing<Vec<u8>>>, Failure> {
            Ok(value
                .try_borrow_mut()
                .map_err(|_| "option storage is borrowed")?
                .take())
        };
        let ego = take(self.ego)?;
        if ego.as_ref().is_some_and(|name| name.is_empty()) {
            return Err("ego name must not be empty".into());
        }
        let room = take(self.room)?;
        let door = take(self.door)?
            .map(|raw| {
                let mut bytes = [0; 32];
                if gnunet_gnsrecord::decode_base32(&raw, &mut bytes)? != bytes.len() {
                    return Err(gnunet_types::Error::Malformed);
                }
                Ok(bytes)
            })
            .transpose()?;
        let mut secret = Zeroizing::new([0; 64]);
        if let Some(raw) = take(self.secret)?
            && gnunet_gnsrecord::decode_base32(&raw, secret.as_mut())? != 64
        {
            return Err("storage secret must encode exactly64 bytes".into());
        }
        let profile = match config.get(b"messenger-rust", b"PROFILE") {
            None => Profile::NATIVE_255,
            Some(b"little-255") => Profile::LITTLE_255,
            Some(b"big-255") => Profile::BIG_255,
            Some(_) => return Err("unsupported explicit Messenger producer profile".into()),
        };
        let timeout = duration(config, b"OPERATION_SECONDS", 30, 1, 3600)?;
        let cleanup = duration(config, b"CLEANUP_SECONDS", 5, 1, 60)?;
        let record_window = duration(config, b"RECORD_WINDOW_SECONDS", 86400, 30, 604800)?;
        let mut limits = Limits::default();
        limits.native.profile = profile;
        limits.core.rooms = 1;
        limits.core.contacts = 128;
        limits.core.sources_per_room = 4;
        limits.core.messages_per_room = number(config, b"MESSAGES", 2048, 16, 65536)?;
        limits.core.epochs_per_room = 64;
        limits.core.groups_per_epoch = 32;
        limits.core.subscriptions_per_room = 128;
        limits.core.events = 128;
        limits.core.missing_per_room = 128;
        limits.core.nonce_per_epoch = 512;
        limits.core.total_bytes = number(
            config,
            b"STATE_BYTES",
            64 * 1024 * 1024,
            1024 * 1024,
            256 * 1024 * 1024,
        )?;
        limits.operation_lifetime = timeout;
        let public = self.public.get()? != 0;
        limits.automatic_epochs = !public;
        limits.core.validate()?;
        Ok(Settings {
            ego,
            room,
            door,
            secret: Some(crypto::records::RecordSecret::from_bytes(*secret)),
            private: self.private.get()? != 0,
            silence: self.silence.get()? != 0,
            history: self.request.get()? != 0 && self.talk.get()? == 0,
            talk: self.talk.get()? != 0,
            public,
            profile,
            timeout,
            cleanup,
            record_window,
            limits,
        })
    }
}
fn number(
    config: &Configuration,
    key: &[u8],
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, Failure> {
    let value = if config.get(b"messenger-rust", key).is_some() {
        usize::try_from(config.get_number(b"messenger-rust", key)?)?
    } else {
        default
    };
    if !(min..=max).contains(&value) {
        return Err("Messenger resource option outside its finite bound".into());
    }
    Ok(value)
}
fn duration(
    config: &Configuration,
    key: &[u8],
    default: usize,
    min: usize,
    max: usize,
) -> Result<Duration, Failure> {
    Ok(Duration::from_secs(u64::try_from(number(
        config, key, default, min, max,
    )?)?))
}
pub(super) struct Settings {
    pub ego: Option<Zeroizing<Vec<u8>>>,
    pub room: Option<Zeroizing<Vec<u8>>>,
    pub door: Option<[u8; 32]>,
    pub secret: Option<crypto::records::RecordSecret>,
    pub private: bool,
    pub silence: bool,
    pub history: bool,
    pub talk: bool,
    pub public: bool,
    pub profile: Profile,
    pub timeout: Duration,
    pub cleanup: Duration,
    pub record_window: Duration,
    pub limits: Limits,
}
