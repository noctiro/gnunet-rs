use crate::{Hello, Limits};
use gnunet_crypto::{EddsaPrivateKey, EddsaPublicKey, EddsaSignature};
use gnunet_types::Error;
use gnunet_wire::official::AbsoluteTime;

/// One validated opaque address URI; the scheme does not identify an available communicator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Address<'a> {
    bytes: &'a [u8],
    scheme_len: usize,
}
impl<'a> Address<'a> {
    /// Validate and borrow one complete official opaque HELLO URI.
    pub fn from_uri(uri: &'a [u8]) -> Result<Self, Error> {
        check_uri(uri)?;
        let scheme_len = uri
            .windows(3)
            .position(|p| p == b"://")
            .ok_or(Error::Malformed)?;
        Ok(Self {
            bytes: uri,
            scheme_len,
        })
    }
    /// Complete URI bytes, excluding the NUL terminator.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
    /// ASCII scheme bytes preceding `://`.
    #[must_use]
    pub fn scheme(self) -> &'a [u8] {
        &self.bytes[..self.scheme_len]
    }
    /// Opaque bytes after `://`; these may be empty or non-UTF-8.
    #[must_use]
    pub fn body(self) -> &'a [u8] {
        &self.bytes[self.scheme_len + 3..]
    }
}

/// Iteration in the actual reference implementation's descending `strcmp` order.
#[derive(Clone, Debug)]
pub struct Addresses<'a> {
    bytes: &'a [u8],
    count: usize,
}
impl<'a> Addresses<'a> {
    pub(crate) const fn new(bytes: &'a [u8], count: usize) -> Self {
        Self { bytes, count }
    }
}
impl<'a> Iterator for Addresses<'a> {
    type Item = Address<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let end = self.bytes.iter().position(|b| *b == 0)?;
        let bytes = &self.bytes[..end];
        self.bytes = &self.bytes[end + 1..];
        self.count -= 1;
        let scheme_len = bytes.windows(3).position(|b| b == b"://")?;
        Some(Address { bytes, scheme_len })
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.count, Some(self.count))
    }
}
impl ExactSizeIterator for Addresses<'_> {}
impl core::iter::FusedIterator for Addresses<'_> {}

/// Result of adding an address to an official builder set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AddAddress {
    /// A new address was inserted in canonical order.
    Added,
    /// The identical address already exists; the builder is unchanged.
    AlreadyPresent,
}

/// A bounded, allocation-free sorted set in caller-owned byte storage.
///
/// Failed additions preserve all existing addresses. Dropping the builder releases
/// its borrow; addresses are public data and are not erased as secrets.
pub struct HelloBuilder<'a> {
    pub(crate) storage: &'a mut [u8],
    pub(crate) used: usize,
    pub(crate) count: usize,
    pub(crate) limits: Limits,
}
impl<'a> HelloBuilder<'a> {
    /// Start an empty set. Both caller limits and the actual slice capacity apply.
    #[must_use]
    pub fn new(storage: &'a mut [u8], limits: Limits) -> Self {
        Self {
            storage,
            used: 0,
            count: 0,
            limits,
        }
    }
    /// Add a NUL-free URI with the RFC3986 scheme grammar, including official `http3`.
    pub fn add_address(&mut self, uri: &[u8]) -> Result<AddAddress, Error> {
        check_uri(uri)?;
        if self.addresses().any(|a| a.as_bytes() == uri) {
            return Ok(AddAddress::AlreadyPresent);
        }
        let length = uri.len().checked_add(1).ok_or(Error::Overflow)?;
        let end = self.preflight(length)?;
        self.storage[self.used..end - 1].copy_from_slice(uri);
        self.storage[end - 1] = 0;
        self.commit_staged(length)?;
        Ok(AddAddress::Added)
    }
    /// Remove an exact address; missing addresses leave the set unchanged.
    pub fn remove_address(&mut self, uri: &[u8]) -> Result<bool, Error> {
        if uri.contains(&0) {
            return Err(Error::InvalidInput);
        }
        let mut offset = 0;
        for address in self.addresses() {
            let length = address.as_bytes().len() + 1;
            if address.as_bytes() == uri {
                self.storage.copy_within(offset + length..self.used, offset);
                self.used -= length;
                self.count -= 1;
                return Ok(true);
            }
            offset += length;
        }
        Ok(false)
    }
    /// Borrow all canonical addresses.
    #[must_use]
    pub fn addresses(&self) -> Addresses<'_> {
        Addresses::new(&self.storage[..self.used], self.count)
    }
    /// Number of unique addresses.
    #[must_use]
    pub const fn address_count(&self) -> usize {
        self.count
    }
    /// NUL-delimited canonical address bytes used by the conditional signature profile.
    #[must_use]
    pub fn address_bytes(&self) -> &[u8] {
        &self.storage[..self.used]
    }
    /// Raw block size, without the HELLO_URI or DHT message envelope.
    pub fn block_len(&self) -> Result<usize, Error> {
        crate::BLOCK_HEADER_LEN
            .checked_add(self.used)
            .ok_or(Error::Overflow)
    }
    /// Actual C `builder_address_list_cmp` semantics: every address in this set is in `other`.
    #[must_use]
    pub fn is_subset_of(&self, other: &Self) -> bool {
        self.addresses().all(|a| other.addresses().any(|b| a == b))
    }
    /// Hash according to an explicitly selected official compilation profile.
    #[must_use]
    pub fn address_hash(&self, profile: crate::SignatureProfile) -> [u8; 64] {
        profile.hash(self.address_bytes())
    }
    /// Attach externally supplied public metadata without claiming signature validity.
    #[must_use]
    pub fn with_signature(
        &self,
        peer: EddsaPublicKey,
        signature: EddsaSignature,
        expiration: AbsoluteTime,
    ) -> Hello<'_> {
        Hello {
            peer,
            signature,
            expiration,
            addresses: self.address_bytes(),
            count: self.count,
        }
    }
    /// Sign the exact official purpose7 region; the profile controls address coverage.
    pub fn sign(
        &self,
        key: &EddsaPrivateKey,
        expiration: AbsoluteTime,
        profile: crate::SignatureProfile,
    ) -> Result<Hello<'_>, Error> {
        let region = crate::signed_payload(expiration, &self.address_hash(profile))?;
        let signature = key.sign(crate::SIGNATURE_PURPOSE, &region)?;
        Ok(self.with_signature(key.public_key(), signature, expiration))
    }
    pub(crate) fn preflight(&self, length: usize) -> Result<usize, Error> {
        if self.count >= self.limits.maximum_addresses {
            return Err(Error::Capacity);
        }
        let end = self.used.checked_add(length).ok_or(Error::Overflow)?;
        if end > self.storage.len() || end > self.limits.maximum_address_bytes {
            return Err(Error::Capacity);
        }
        Ok(end)
    }
    pub(crate) fn commit_staged(&mut self, length: usize) -> Result<(), Error> {
        let end = self.used + length;
        let candidate = &self.storage[self.used..end - 1];
        check_uri(candidate)?;
        let mut insert = self.used;
        let mut offset = 0;
        for previous in self.addresses() {
            if previous.as_bytes() == candidate {
                return Err(Error::Malformed);
            }
            if candidate > previous.as_bytes() && insert == self.used {
                insert = offset;
            }
            offset += previous.as_bytes().len() + 1;
        }
        self.storage[insert..end].rotate_right(length);
        self.used = end;
        self.count += 1;
        Ok(())
    }
    pub(crate) fn parse_raw(&mut self, mut bytes: &[u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            let end = bytes.iter().position(|b| *b == 0).ok_or(Error::Truncated)?;
            if self.add_address(&bytes[..end])? == AddAddress::AlreadyPresent {
                return Err(Error::Malformed);
            }
            bytes = &bytes[end + 1..];
        }
        Ok(())
    }
    pub(crate) fn finish(
        self,
        peer: EddsaPublicKey,
        signature: EddsaSignature,
        expiration: AbsoluteTime,
    ) -> Hello<'a> {
        Hello {
            peer,
            signature,
            expiration,
            addresses: &self.storage[..self.used],
            count: self.count,
        }
    }
}

pub(crate) fn check_scheme(scheme: &[u8]) -> Result<(), Error> {
    let Some((&first, rest)) = scheme.split_first() else {
        return Err(Error::Malformed);
    };
    // The official HTTP/3 communicator uses "http3". The pinned C HELLO
    // checker rejects its digit; URI syntax, unlike that bug, permits it.
    if !first.is_ascii_alphabetic()
        || rest
            .iter()
            .any(|b| !b.is_ascii_alphanumeric() && !matches!(*b, b'+' | b'-' | b'.'))
    {
        return Err(Error::Malformed);
    }
    Ok(())
}
pub(crate) fn check_uri(uri: &[u8]) -> Result<(), Error> {
    if uri.contains(&0) {
        return Err(Error::Malformed);
    }
    let n = uri
        .windows(3)
        .position(|p| p == b"://")
        .ok_or(Error::Malformed)?;
    check_scheme(&uri[..n])
}

/// The public C helper extracts bytes before the first `-`, rather than the URI scheme.
#[must_use]
pub fn address_to_prefix(address: &[u8]) -> Option<&[u8]> {
    let effective = address.split(|b| *b == 0).next()?;
    effective
        .iter()
        .position(|b| *b == b'-')
        .map(|end| &effective[..end])
}
