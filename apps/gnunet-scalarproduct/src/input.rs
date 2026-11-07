//! Actual ordinary -e/-p/-k vector/role selection and finite configuration.
use crate::run::Failure;
use gnunet_scalarproduct_client_host::{ELEMENT_BYTES, Element, Limits, Role};
use std::time::{Duration, Instant};
pub(super) struct Selection {
    pub role: Role,
    pub elements: Vec<[u8; ELEMENT_BYTES]>,
}
#[derive(Clone, Copy)]
pub(super) struct Settings {
    pub native: Limits,
    pub total: Duration,
    pub output: Duration,
    pub max_output: usize,
    pub max_input: usize,
    pub resolver: gnunet_resolver_broker::Limits,
}
fn size(c: &gnunet_config::Configuration, key: &[u8], default: usize) -> Result<usize, Failure> {
    Ok(c.get(b"scalarproduct-client-rust", key)
        .map(|_| c.get_size(b"scalarproduct-client-rust", key))
        .transpose()?
        .map(usize::try_from)
        .transpose()?
        .unwrap_or(default))
}
fn time(
    c: &gnunet_config::Configuration,
    key: &[u8],
    default: Duration,
) -> Result<Duration, Failure> {
    let d = c
        .get(b"scalarproduct-client-rust", key)
        .map(|_| c.get_time(b"scalarproduct-client-rust", key))
        .transpose()?
        .map(Duration::from_micros)
        .unwrap_or(default);
    if d.is_zero()
        || d.as_micros() >= u128::from(u64::MAX)
        || Instant::now().checked_add(d).is_none()
    {
        return Err("SCALARPRODUCT deadlines must be finite/nonzero".into());
    }
    Ok(d)
}
impl Settings {
    pub(super) fn read(c: &gnunet_config::Configuration) -> Result<Self, Failure> {
        let d = Limits::default();
        let native = Limits {
            frame_bytes: size(c, b"MAX_FRAME_BYTES", d.frame_bytes)?,
            elements: size(c, b"MAX_ELEMENTS", d.elements)?,
            vector_bytes: size(c, b"VECTOR_BYTES", d.vector_bytes)?,
            result_bytes: size(c, b"RESULT_BYTES", d.result_bytes)?,
            io_slice_bytes: size(c, b"IO_SLICE_BYTES", d.io_slice_bytes)?,
            initial_timeout: time(c, b"INITIAL_TIMEOUT", d.initial_timeout)?,
            write_timeout: time(c, b"WRITE_TIMEOUT", d.write_timeout)?,
            input_timeout: time(c, b"INPUT_TIMEOUT", d.input_timeout)?,
        };
        let max_output = size(c, b"MAX_OUTPUT_BYTES", 262144)?;
        let max_input = size(c, b"MAX_INPUT_BYTES", 4 << 20)?;
        if !(184..=65535).contains(&native.frame_bytes)
            || native.elements == 0
            || native.elements > 1048576
            || native.vector_bytes == 0
            || native.vector_bytes > 256 << 20
            || native.result_bytes > 65519
            || native.io_slice_bytes == 0
            || !(16..=1 << 20).contains(&max_output)
            || !(1..=16 << 20).contains(&max_input)
        {
            return Err("SCALARPRODUCT native/input/output resource bounds invalid".into());
        }
        Ok(Self {
            native,
            total: time(c, b"TOTAL_TIMEOUT", Duration::from_secs(600))?,
            output: time(c, b"OUTPUT_TIMEOUT", Duration::from_secs(10))?,
            max_output,
            max_input,
            resolver: Default::default(),
        })
    }
}
impl Selection {
    pub(super) fn read(
        elements: Option<Vec<u8>>,
        key: Option<Vec<u8>>,
        peer: Option<Vec<u8>>,
        args: &[Vec<u8>],
        settings: Settings,
    ) -> Result<Self, Failure> {
        if !args.is_empty() {
            return Err("SCALARPRODUCT accepts -e/--elements, -k/--key and optional -p/--peer, without positional arguments".into());
        }
        let key = key
            .filter(|k| !k.is_empty())
            .ok_or("SCALARPRODUCT needs a nonempty -k/--key transaction identifier")?;
        if key.len() > settings.max_input || key.contains(&0) {
            return Err(
                "SCALARPRODUCT transaction identifier exceeds limits or contains NUL".into(),
            );
        }
        let session = gnunet_crypto::hash512(&key);
        let role = if let Some(peer) = peer {
            if peer.len() != 52 {
                return Err("SCALARPRODUCT peer needs the full52-character public identity".into());
            }
            let mut c = gnunet_config::Configuration::new(Default::default());
            c.set_value(b"peer", b"id", Some(&peer))?;
            let mut id = [0; 32];
            c.get_data(b"peer", b"id", &mut id)?;
            Role::Alice { session, peer: id }
        } else {
            Role::Bob { session }
        };
        let input = elements.ok_or("SCALARPRODUCT needs -e/--elements key,value; entries")?;
        if input.len() > settings.max_input || input.contains(&0) {
            return Err("SCALARPRODUCT vector text exceeds limits or contains NUL".into());
        }
        let input =
            if input.first() == Some(&b'\'') && input.last() == Some(&b'\'') && input.len() >= 2 {
                &input[1..input.len() - 1]
            } else {
                input.as_slice()
            };
        if input.is_empty() || input.last() != Some(&b';') {
            return Err("SCALARPRODUCT vector must contain nonempty key,value; entries with trailing semicolon".into());
        }
        let count = input.iter().filter(|b| **b == b';').count();
        if count == 0 || count > settings.native.elements {
            return Err("SCALARPRODUCT vector element count exceeds profile".into());
        }
        let mut values = Vec::new();
        values.try_reserve_exact(count)?;
        if values
            .capacity()
            .checked_mul(ELEMENT_BYTES)
            .is_none_or(|b| b > settings.native.vector_bytes)
        {
            return Err("SCALARPRODUCT actual vector capacity exceeds profile".into());
        }
        for tuple in input[..input.len() - 1].split(|b| *b == b';') {
            let at = tuple
                .iter()
                .rposition(|b| *b == b',')
                .ok_or("SCALARPRODUCT tuple needs key,value")?;
            let (name, value) = tuple.split_at(at);
            if name.is_empty() || value.len() < 2 {
                return Err("SCALARPRODUCT tuple has an empty key/value".into());
            }
            let value = std::str::from_utf8(value[1..].trim_ascii())?.parse::<i64>()?;
            let hash = gnunet_crypto::hash512(name);
            values.push(Element { key: &hash, value }.encode());
        }
        Ok(Self {
            role,
            elements: values,
        })
    }
}
