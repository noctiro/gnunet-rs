use crate::{Failure, options::Settings};
use gnunet_gnsrecord::RecordType;
use gnunet_gnsrecord_text::{Codec, Profile, Workspace};
use zeroize::Zeroizing;

pub(super) fn bytes(length: usize) -> Result<Zeroizing<Vec<u8>>, Failure> {
    let mut out = Zeroizing::new(Vec::new());
    out.try_reserve_exact(length)?;
    if out.capacity() > length {
        return Err("allocation exceeds the admitted exact byte bound".into());
    }
    out.resize(length, 0);
    Ok(out)
}
pub(super) struct Buffers {
    stage: Zeroizing<Vec<u8>>,
    names: Zeroizing<Vec<u8>>,
    work: Zeroizing<Vec<u8>>,
    result: Zeroizing<Vec<u8>>,
    settings: Settings,
}
impl Buffers {
    pub fn new(settings: Settings) -> Result<Self, Failure> {
        let capacity = settings.text_bytes.max(65535);
        Ok(Self {
            stage: bytes(capacity)?,
            names: bytes(1024)?,
            work: bytes(2048)?,
            result: bytes(capacity)?,
            settings,
        })
    }
    fn convert(&mut self, kind: RecordType, input: &[u8], format: bool) -> Result<usize, Failure> {
        let mut idna_work = gnunet_idna::Workspace::new();
        let idna = gnunet_idna::Backend::new(
            &mut idna_work,
            gnunet_idna::Limits::GNUNET,
            gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
        );
        let limits = gnunet_gnsrecord_text::Limits {
            input_bytes: self.settings.text_bytes,
            output_bytes: self.result.len(),
            ..Default::default()
        };
        let mut codec = Codec::new(
            &idna,
            Workspace::new(&mut self.stage, &mut self.names, &mut self.work),
            Profile::NATIVE_255,
            limits,
        )?
        .with_abd_layout(self.settings.layout)?;
        let n = if format {
            codec.value_to_string(kind, input, &mut self.result)?
        } else {
            codec.string_to_value(kind, std::str::from_utf8(input)?, &mut self.result)?
        };
        Ok(n)
    }
    pub fn parse(&mut self, kind: RecordType, text: &[u8]) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let n = self.convert(kind, text, false)?;
        let mut out = bytes(n)?;
        out.copy_from_slice(&self.result[..n]);
        Ok(out)
    }
    pub fn format(&mut self, kind: RecordType, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Failure> {
        let n = self.convert(kind, data, true)?;
        let mut out = bytes(n)?;
        out.copy_from_slice(&self.result[..n]);
        Ok(out)
    }
}
#[derive(Clone, Copy)]
pub(super) struct Expiration {
    pub value: u64,
    pub relative: bool,
}
pub(super) fn expiration(text: &[u8], absolute_only: bool) -> Result<Expiration, Failure> {
    if text == b"never" {
        return Ok(Expiration {
            value: u64::MAX,
            relative: false,
        });
    }
    if !absolute_only && let Ok(value) = gnunet_config::parse_relative_time(text) {
        return Ok(Expiration {
            value,
            relative: true,
        });
    }
    Ok(Expiration {
        value: gnunet_program_host::helpers::parse_absolute(text)?,
        relative: false,
    })
}
