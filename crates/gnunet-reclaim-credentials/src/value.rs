//! Credential-specific selection/string conversion over shared JSON values.
use crate::JsonString;
use core::fmt;
use gnunet_json::Format;
pub use gnunet_json::ValueKind;
use gnunet_reclaim::Sensitive;
use gnunet_types::Error;
/// A complete parsed value with the original credential-specific conversion API.
#[derive(Clone, Copy)]
pub struct JsonValue<'a> {
    pub(crate) inner: gnunet_json::Value<'a>,
}
impl<'a> JsonValue<'a> {
    /// Complete actual JSON value category.
    pub fn kind(self) -> ValueKind {
        self.inner.kind()
    }
    /// Explicit original JSON bytes tied to the original zeroizing workspace.
    pub fn expose_json(self) -> Sensitive<'a> {
        Sensitive::new(self.inner.expose_json())
    }
    /// Decoded JSON string view, refusing coercion of other value types.
    pub fn string(self) -> Result<JsonString<'a>, Error> {
        self.inner.string()
    }
    /// Exact integer NumericDate-compatible value; real1.0 is not an integer.
    pub fn integer(self) -> Result<i64, Error> {
        self.inner.integer()
    }
    /// Required JSON-derived STRING bytes, preserving C outer-string quote
    /// stripping/final-NUL semantics; other JSON values retain complete JSON.
    pub fn attribute_len(self) -> Result<usize, Error> {
        if self.kind() == ValueKind::String {
            self.string()?
                .encoded_len_with(false, Format::Jansson)?
                .checked_add(1)
                .ok_or(Error::Overflow)
        } else {
            self.inner.encoded_len_with(Format::Jansson)
        }
    }
    /// Write after complete preflight using the active plugin's Jansson default
    /// real precision and uppercase control escapes throughout nested values.
    pub fn write_attribute(self, out: &mut [u8]) -> Result<usize, Error> {
        let n = self.attribute_len()?;
        let out = out.get_mut(..n).ok_or(Error::Capacity)?;
        if self.kind() == ValueKind::String {
            self.string()?
                .encode_with(&mut out[..n - 1], false, Format::Jansson)?;
            out[n - 1] = 0;
        } else {
            self.inner.encode_with(out, Format::Jansson)?;
        }
        Ok(n)
    }
}
impl fmt::Debug for JsonValue<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JsonValue([REDACTED])")
    }
}
/// One actual selected attribute; raw names remain decoded and case preserving.
#[derive(Clone, Copy, Debug)]
pub struct Claim<'a> {
    /// Original decoded key (address uses the member's own unprefixed key).
    pub name: JsonString<'a>,
    /// Complete actual JSON value subtree.
    pub value: JsonValue<'a>,
}
/// Insertion-order plugin claim selection, allocating no data or linked list.
pub struct ClaimIter<'a> {
    outer: Option<gnunet_json::Members<'a>>,
    address: Option<gnunet_json::Members<'a>>,
}
impl<'a> ClaimIter<'a> {
    pub(crate) fn new(root: gnunet_json::Value<'a>) -> Self {
        Self {
            outer: root.members().ok(),
            address: None,
        }
    }
}
impl<'a> Iterator for ClaimIter<'a> {
    type Item = Claim<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(address) = self.address.as_mut() {
                if let Some(member) = address.next() {
                    return Some(Claim {
                        name: member.name,
                        value: JsonValue {
                            inner: member.value,
                        },
                    });
                }
                self.address = None;
            }
            let member = self.outer.as_mut()?.next()?;
            if [b"iss".as_slice(), b"jti", b"exp", b"iat", b"nbf", b"aud"]
                .iter()
                .any(|key| member.name.eq_ascii(key))
            {
                continue;
            }
            if member.name.eq_ascii(b"address") {
                self.address = member.value.members().ok();
                continue;
            }
            return Some(Claim {
                name: member.name,
                value: JsonValue {
                    inner: member.value,
                },
            });
        }
    }
}
impl core::iter::FusedIterator for ClaimIter<'_> {}
