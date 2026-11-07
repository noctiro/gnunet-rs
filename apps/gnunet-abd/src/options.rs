use crate::Failure;
use gnunet_abd::Principal;
use gnunet_config::Configuration;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use gnunet_wire::official::abd::RecordLayout;
use std::time::Duration;
use zeroize::Zeroizing;

/// No private key option exists. All keys below are public identifiers or a
/// real ego name selected through the original IDENTITY lookup.
pub(super) struct Arguments {
    issuer_store: Target<i32>,
    subject_store: Target<i32>,
    sign: Target<i32>,
    collect: Target<i32>,
    verify: Target<i32>,
    private: Target<i32>,
    forward: Target<i32>,
    backward: Target<i32>,
    subject: Target<Option<Vec<u8>>>,
    delegates: Target<Option<Vec<u8>>>,
    issuer: Target<Option<Vec<u8>>>,
    ego: Target<Option<Vec<u8>>>,
    attribute: Target<Option<Vec<u8>>>,
    expiration: Target<Option<Vec<u8>>>,
    import: Target<Option<Vec<u8>>>,
    timeout: Target<u64>,
}
impl Arguments {
    pub fn new() -> Self {
        Self {
            issuer_store: Target::new(0),
            subject_store: Target::new(0),
            sign: Target::new(0),
            collect: Target::new(0),
            verify: Target::new(0),
            private: Target::new(0),
            forward: Target::new(0),
            backward: Target::new(0),
            subject: Target::new(None),
            delegates: Target::new(None),
            issuer: Target::new(None),
            ego: Target::new(None),
            attribute: Target::new(None),
            expiration: Target::new(None),
            import: Target::new(None),
            timeout: Target::new(0),
        }
    }
    pub fn options(&self) -> Options<'static> {
        let mut out = Options::new();
        for (short, long, description, target) in [
            (
                b'U',
                b"createIssuerSide".as_slice(),
                b"Prepend an ATTR record in the actual ego zone".as_slice(),
                self.issuer_store.clone(),
            ),
            (
                b'C',
                b"createSubjectSide",
                b"Import a signed DEL for the actual subject ego at @",
                self.subject_store.clone(),
            ),
            (
                b'S',
                b"signSubjectSide",
                b"Issue and print a real purpose28 DEL using the ego",
                self.sign.clone(),
            ),
            (
                b'g',
                b"collect",
                b"Collect PRIVATE DEL leaves using the actual ego",
                self.collect.clone(),
            ),
            (
                b'V',
                b"verify",
                b"Verify a subject against an issuer role",
                self.verify.clone(),
            ),
            (
                b'P',
                b"private",
                b"Store the new record with the original PRIVATE flag",
                self.private.clone(),
            ),
            (
                b'F',
                b"forward",
                b"Enable forward resolution",
                self.forward.clone(),
            ),
            (
                b'B',
                b"backward",
                b"Enable backward resolution",
                self.backward.clone(),
            ),
        ] {
            out.add(helpers::flag(short, long, description, target));
        }
        for (short, long, argument, description, target) in [
            (
                b's',
                b"subject".as_slice(),
                b"KEY [ROLE]".as_slice(),
                b"Subject public key; for -U use standard ATTR text".as_slice(),
                self.subject.clone(),
            ),
            (
                b'd',
                b"delegate",
                b"DEL,...",
                b"Comma-separated standard signed DEL leaves; absence permits direct GNS",
                self.delegates.clone(),
            ),
            (
                b'i',
                b"issuer",
                b"KEY",
                b"Public issuer/trust-anchor key",
                self.issuer.clone(),
            ),
            (
                b'e',
                b"ego",
                b"NAME",
                b"Existing IDENTITY ego name; never a serialized private key",
                self.ego.clone(),
            ),
            (
                b'a',
                b"attribute",
                b"ROLE",
                b"Original issuer role; also -U record label",
                self.attribute.clone(),
            ),
            (
                b'T',
                b"ttl",
                b"TIME",
                b"Store TTL: relative/calendar/epoch seconds/never; -S requires absolute/never",
                self.expiration.clone(),
            ),
            (
                b'x',
                b"import",
                b"DEL",
                b"Exact standard signed DEL record text for -C",
                self.import.clone(),
            ),
        ] {
            out.add(helpers::string(short, long, argument, description, target));
        }
        out.add(helpers::relative_time(
            0,
            b"timeout",
            b"DURATION",
            b"Finite whole original identity/request/output deadline",
            self.timeout.clone(),
        ));
        out
    }
    pub fn selection(
        &self,
        remaining: &[Vec<u8>],
        settings: &Settings,
    ) -> Result<Selection, Failure> {
        if !remaining.is_empty() {
            return Err("ABD takes options, not positional/private-key arguments".into());
        }
        let flags = [
            self.issuer_store.get()?,
            self.subject_store.get()?,
            self.sign.get()?,
            self.collect.get()?,
            self.verify.get()?,
        ];
        if flags.iter().filter(|x| **x != 0).count() != 1 {
            return Err("select exactly one ABD action: -U, -C, -S, -g or -V".into());
        }
        let get = |target: &Target<Option<Vec<u8>>>,
                   name: &str,
                   max: usize|
         -> Result<Vec<u8>, Failure> {
            target.with(|value| -> Result<Vec<u8>, Failure> {
                let bytes = value.as_deref().ok_or_else(|| format!("missing {name}"))?;
                copy(bytes, max, false)
            })?
        };
        let attr = || get(&self.attribute, "--attribute", settings.name_bytes);
        let ego = || get(&self.ego, "--ego", settings.identity.name_bytes);
        let subject = || get(&self.subject, "--subject", settings.text_bytes);
        let issuer = || public_key(&get(&self.issuer, "--issuer", 58)?);
        let expiration = || get(&self.expiration, "--ttl", 256);
        let f = self.forward.get()? != 0;
        let b = self.backward.get()? != 0;
        let direction = if !f && !b {
            3
        } else {
            u16::from(f) | if b { 2 } else { 0 }
        };
        let private = self.private.get()? != 0;
        let action = if flags[0] != 0 {
            Action::IssuerStore {
                ego: ego()?,
                attribute: get(&self.attribute, "--attribute record label", 255)?,
                policy: Zeroizing::new(subject()?),
                expiration: expiration()?,
                private,
            }
        } else if flags[1] != 0 {
            Action::SubjectStore {
                ego: ego()?,
                record: Zeroizing::new(get(&self.import, "--import", settings.text_bytes)?),
                private,
            }
        } else if flags[2] != 0 {
            let bytes = subject()?;
            let text = std::str::from_utf8(&bytes)?;
            let mut parts = text.split_ascii_whitespace();
            let subject = public_key(parts.next().ok_or("empty --subject")?.as_bytes())?;
            let role = parts
                .next()
                .map(|s| copy(s.as_bytes(), settings.name_bytes, false))
                .transpose()?;
            if parts.next().is_some() {
                return Err(
                    "signed subject is KEY or KEY ROLE, with no discarded trailing fields".into(),
                );
            }
            Action::Sign {
                ego: ego()?,
                subject,
                subject_role: role,
                attribute: attr()?,
                expiration: expiration()?,
            }
        } else if flags[3] != 0 {
            Action::Collect {
                ego: ego()?,
                issuer: issuer()?,
                attribute: attr()?,
                direction,
            }
        } else {
            let delegates = self.delegates.with(|value| {
                copy(
                    value.as_deref().unwrap_or_default(),
                    settings.text_bytes,
                    true,
                )
            })??;
            Action::Verify {
                subject: public_key(&subject()?)?,
                issuer: issuer()?,
                attribute: attr()?,
                delegates: Zeroizing::new(delegates),
                direction,
            }
        };
        if private
            && !matches!(
                action,
                Action::IssuerStore { .. } | Action::SubjectStore { .. }
            )
        {
            return Err("--private only applies to record creation".into());
        }
        if (f || b) && !matches!(action, Action::Collect { .. } | Action::Verify { .. }) {
            return Err("--forward/--backward only apply to collect/verify".into());
        }
        let timeout = self.timeout.get()?;
        let lifetime = if timeout == 0 {
            settings.operation
        } else {
            Duration::from_micros(timeout)
        };
        if lifetime.is_zero()
            || lifetime.as_micros() >= u128::from(u64::MAX)
            || std::time::Instant::now().checked_add(lifetime).is_none()
        {
            return Err("--timeout must be finite and representable".into());
        }
        Ok(Selection { action, lifetime })
    }
}
fn copy(bytes: &[u8], max: usize, empty: bool) -> Result<Vec<u8>, Failure> {
    if (!empty && bytes.is_empty()) || bytes.len() > max || bytes.contains(&0) {
        return Err("invalid or over-bound ABD option value".into());
    }
    std::str::from_utf8(bytes)?;
    let mut value = Vec::new();
    value.try_reserve_exact(bytes.len())?;
    if value.capacity() > max {
        return Err("ABD option allocation exceeds its bound".into());
    }
    value.extend_from_slice(bytes);
    Ok(value)
}
pub(super) fn public_key(bytes: &[u8]) -> Result<Principal, Failure> {
    let text = std::str::from_utf8(bytes)?;
    Ok(Principal::new(
        gnunet_gnsrecord::ZoneKey::from_ztld(text)?.to_wire(),
    )?)
}
pub(super) struct Selection {
    pub action: Action,
    pub lifetime: Duration,
}
pub(super) enum Action {
    IssuerStore {
        ego: Vec<u8>,
        attribute: Vec<u8>,
        policy: Zeroizing<Vec<u8>>,
        expiration: Vec<u8>,
        private: bool,
    },
    SubjectStore {
        ego: Vec<u8>,
        record: Zeroizing<Vec<u8>>,
        private: bool,
    },
    Sign {
        ego: Vec<u8>,
        subject: Principal,
        subject_role: Option<Vec<u8>>,
        attribute: Vec<u8>,
        expiration: Vec<u8>,
    },
    Collect {
        ego: Vec<u8>,
        issuer: Principal,
        attribute: Vec<u8>,
        direction: u16,
    },
    Verify {
        subject: Principal,
        issuer: Principal,
        attribute: Vec<u8>,
        delegates: Zeroizing<Vec<u8>>,
        direction: u16,
    },
}
#[derive(Clone, Copy)]
pub(super) struct Settings {
    pub operation: Duration,
    pub output_bytes: usize,
    pub text_bytes: usize,
    pub records: usize,
    pub name_bytes: usize,
    pub uncertainty: u64,
    pub layout: RecordLayout,
    pub identity: gnunet_identity_client_host::Limits,
    pub namestore: gnunet_namestore_client_host::Limits,
    pub abd: gnunet_abd_client_host::Limits,
    pub resolver: gnunet_resolver_broker::Limits,
}
impl Settings {
    pub fn read(c: &Configuration) -> Result<Self, Failure> {
        let section = b"abd-command-rust";
        let number = |key: &[u8], default: u64| -> Result<u64, Failure> {
            Ok(c.get(section, key)
                .map(|_| c.get_number(section, key))
                .transpose()?
                .unwrap_or(default))
        };
        let size = |key: &[u8], default: usize| -> Result<usize, Failure> {
            Ok(usize::try_from(
                c.get(section, key)
                    .map(|_| c.get_size(section, key))
                    .transpose()?
                    .unwrap_or(u64::try_from(default)?),
            )?)
        };
        let life = c
            .get(section, b"OPERATION_TIMEOUT")
            .map(|_| c.get_time(section, b"OPERATION_TIMEOUT"))
            .transpose()?
            .unwrap_or(120_000_000);
        let operation = Duration::from_micros(life);
        let output_bytes = size(b"OUTPUT_BYTES", 1 << 20)?;
        let text_bytes = size(b"TEXT_BYTES", 262140)?;
        let records = usize::try_from(number(b"MAX_RECORDS", 4096)?)?;
        let uncertainty = number(b"UTC_UNCERTAINTY_US", 0)?;
        let name_bytes = size(b"NAME_BYTES", gnunet_abd::Limits::default().name_bytes)?;
        if life == 0
            || life == u64::MAX
            || std::time::Instant::now().checked_add(operation).is_none()
            || !(1..=(64 << 20)).contains(&output_bytes)
            || !(1..=(4 << 20)).contains(&text_bytes)
            || !(1..=65535).contains(&records)
            || !(1..=65535).contains(&name_bytes)
            || uncertainty == u64::MAX
        {
            return Err("invalid finite ABD command resource profile".into());
        }
        let layout = RecordLayout {
            align64: u8::try_from(number(
                b"ATTR_ALIGN64",
                u64::from(RecordLayout::native().align64),
            )?)?,
        };
        layout.validate()?;
        let identity = gnunet_identity_client_host::Limits {
            operations: 1,
            egos: 0,
            reconnect: false,
            ..Default::default()
        };
        let namestore = gnunet_namestore_client_host::Limits {
            operations: 1,
            records,
            reconnect: false,
            ..Default::default()
        };
        let abd = gnunet_abd_client_host::Limits {
            records,
            ..Default::default()
        };
        abd.validate()?;
        Ok(Self {
            operation,
            output_bytes,
            text_bytes,
            records,
            name_bytes,
            uncertainty,
            layout,
            identity,
            namestore,
            abd,
            resolver: Default::default(),
        })
    }
}
