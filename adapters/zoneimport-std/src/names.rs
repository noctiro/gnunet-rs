//! Complete explicit IDNA conversion over one reusable caller-owned workspace.
use gnunet_dns::Idna;
use gnunet_types::Error;

/// Small bounded reusable name conversion owner; no system resolver or fallback.
pub struct Names {
    work: gnunet_idna::Workspace,
}
impl Default for Names {
    fn default() -> Self {
        Self {
            work: gnunet_idna::Workspace::new(),
        }
    }
}
impl Names {
    fn prepare(&mut self, input: &[u8], hostname: bool) -> Result<String, crate::Error> {
        let mut output = [0; 255];
        let backend = gnunet_idna::Backend::new(
            &mut self.work,
            gnunet_idna::Limits {
                maximum_input_bytes: 4096,
            },
            gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
        );
        // This exact scope contains no allocation or live owner operation.
        // Capacity here means input cannot fit a DNS name, not allocator failure.
        let used = backend
            .to_ascii(input, &mut output)
            .map_err(|error| match error {
                Error::Unavailable | Error::Overflow => crate::Error::Core(error),
                other => crate::Error::InvalidName(other),
            })?;
        let value = core::str::from_utf8(&output[..used])
            .map_err(|_| crate::Error::InvalidName(Error::Malformed))?;
        let value = value.strip_suffix('.').unwrap_or(value);
        if value.is_empty()
            || value.len() > 253
            || !value.is_ascii()
            || value
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
            || value
                .split('.')
                .any(|label| label.is_empty() || label.len() > 63)
            || hostname && !value.contains('.')
        {
            return Err(crate::Error::InvalidName(Error::Malformed));
        }
        let mut name = String::new();
        // Real allocator failure remains fatal independently of input validity.
        name.try_reserve_exact(value.len())
            .map_err(|_| crate::Error::Core(Error::Capacity))?;
        name.push_str(value);
        name.make_ascii_lowercase();
        Ok(name)
    }
    /// Canonical ASCII zone metadata; decoding grants no identity authority.
    pub fn zone(&mut self, input: &[u8]) -> Result<String, Error> {
        self.prepare(input, false).map_err(|error| match error {
            crate::Error::InvalidName(error) | crate::Error::Core(error) => error,
            _ => Error::InvalidInput,
        })
    }
    /// Actual stdin FQDN. Local allocation/capability failures remain distinct
    /// from syntax/output-name refusals and must not be silently skipped.
    pub fn hostname(&mut self, input: &[u8]) -> Result<String, Error> {
        self.prepare(input, true).map_err(|error| match error {
            crate::Error::InvalidName(error) | crate::Error::Core(error) => error,
            _ => Error::InvalidInput,
        })
    }
    pub(crate) fn input(&mut self, input: &[u8]) -> Result<String, crate::Error> {
        self.prepare(input, true)
    }
    pub(crate) fn inventory(&mut self, input: &[u8]) -> Result<String, crate::Error> {
        self.prepare(input, false)
    }
    /// Decode one actual canonical ASCII label for the existing NAMESTORE API.
    /// The returned UTF-8 bytes are ordinary label data, never private material.
    pub fn label(&mut self, input: &str) -> Result<Vec<u8>, Error> {
        let mut output = [0; 255];
        let backend = gnunet_idna::Backend::new(
            &mut self.work,
            gnunet_idna::Limits {
                maximum_input_bytes: 4096,
            },
            gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
        );
        let used = backend.to_unicode_label(input.as_bytes(), &mut output)?;
        let value = &output[..used];
        if value.is_empty() || value.contains(&0) {
            return Err(Error::Malformed);
        }
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(used).map_err(|_| Error::Capacity)?;
        bytes.extend_from_slice(value);
        Ok(bytes)
    }
    /// Decode a canonical whole control-zone name without changing its actual
    /// IDENTITY owner mapping. Only newly requested CREATE uses this spelling.
    pub fn domain(&mut self, input: &str, maximum: usize) -> Result<Vec<u8>, Error> {
        let mut output = Vec::new();
        output
            .try_reserve_exact(maximum)
            .map_err(|_| Error::Capacity)?;
        for label in input.split('.') {
            let part = self.label(label)?;
            let extra = part
                .len()
                .checked_add(usize::from(!output.is_empty()))
                .ok_or(Error::Overflow)?;
            if output
                .len()
                .checked_add(extra)
                .is_none_or(|size| size > maximum)
            {
                return Err(Error::Capacity);
            }
            if !output.is_empty() {
                output.push(b'.');
            }
            output.extend_from_slice(&part);
        }
        Ok(output)
    }
    /// Borrow the same complete backend for synchronous response conversion.
    pub fn backend(&mut self) -> gnunet_idna::Backend<'_> {
        gnunet_idna::Backend::new(
            &mut self.work,
            gnunet_idna::Limits {
                maximum_input_bytes: 4096,
            },
            gnunet_idna::NativeProfile::Libunistring1_5Unicode18_0,
        )
    }
}
