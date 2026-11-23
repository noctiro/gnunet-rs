//! One shared expansion allowance for compressed metadata within a container.

mod brotli;
mod gzip;

use gnunet_fs_codec::{DeflateFormat, Inflate};

const MAX_EXPANDED_BYTES: usize = 1 << 20;

#[cfg(test)]
pub(super) const XMP_BROTLI: &[u8] = b"\
    \x1f\x90\x00\x00\x64\x6a\x5e\xaa\x8f\xec\x38\x29\xef\x3e\x34\xcc\
    \xf4\x80\x8b\x14\x5b\xf6\x65\x4a\xd7\x6e\x0d\x98\xc8\x89\xb6\xfc\
    \xf2\xac\x77\x38\x2a\x2b\x7e\xa2\x8e\x0e\x1f\x75\xd7\xb5\x39\x8c\
    \xbd\xef\x4b\x07\x82\x3f\x97\x4c\x4a\x72\x54\x0d\x39\xff\xe5\xd2\
    \x1f\x59\x4e\x8c\x02\xef\x70\xb4\x09\xc2\x16\x96\x93\xea\x6a\x35\
    \x75\x5c\xbf\x56\x0a\x36\xce\x6e\xdd\x98\xa0\x9c\x21\xb0\x39\x69\
    \x7f\xfd\x3e\x2a\xf5\xd1\x9f\x88\x05\x1e\x3b\x1c\x95\x15\x01";

#[derive(Clone, Copy)]
pub(super) enum Encoding {
    Zlib,
    Deflate,
    Brotli,
    Gzip,
}

/// PDF permits RFC 9841 large windows in raw Brotli members.
pub(super) fn decode_pdf_brotli(input: &[u8], output: &mut [u8]) -> Option<usize> {
    brotli::decode(input, output, brotli::Window::Large)
}

/// Interpretation of the content-encoding field used by HEIF metadata.
#[derive(Clone, Copy)]
pub(super) enum ContentCoding {
    Identity,
    Compressed(Encoding),
}

impl ContentCoding {
    pub(super) fn parse(token: &[u8], deflate: DeflateFormat) -> Option<Self> {
        let is = |expected: &[u8]| token.eq_ignore_ascii_case(expected);
        let encoding = if token.is_empty() || is(b"identity") {
            return Some(Self::Identity);
        } else if is(b"deflate") {
            match deflate {
                DeflateFormat::Zlib => Encoding::Zlib,
                DeflateFormat::Raw => Encoding::Deflate,
            }
        } else if is(b"compress_zlib") || is(b"application/zlib") {
            Encoding::Zlib
        } else if is(b"br") {
            Encoding::Brotli
        } else if is(b"gzip") || is(b"x-gzip") || is(b"application/gzip") {
            Encoding::Gzip
        } else {
            return None;
        };
        Some(Self::Compressed(encoding))
    }

    pub(super) const fn encoding(self) -> Option<Encoding> {
        match self {
            Self::Identity => None,
            Self::Compressed(encoding) => Some(encoding),
        }
    }
}

pub(super) struct Decompression {
    remaining: usize,
    output: Vec<u8>,
    inflater: Option<Inflate>,
}

impl Decompression {
    pub(super) fn new(remaining: usize) -> Self {
        Self {
            remaining,
            output: Vec::new(),
            inflater: None,
        }
    }

    pub(super) fn for_probe(probe_bytes: usize) -> Self {
        Self::new(probe_bytes.saturating_mul(4).min(MAX_EXPANDED_BYTES))
    }

    pub(super) fn decode(&mut self, encoding: Encoding, input: &[u8]) -> Option<&[u8]> {
        self.decode_limited(encoding, input, self.remaining)
    }

    pub(super) fn decode_limited(
        &mut self,
        encoding: Encoding,
        input: &[u8],
        limit: usize,
    ) -> Option<&[u8]> {
        let capacity = limit.min(self.remaining);
        if capacity == 0 || input.is_empty() {
            return None;
        }
        if self.output.len() < capacity {
            if self
                .output
                .try_reserve_exact(capacity - self.output.len())
                .is_err()
            {
                self.remaining = 0;
                return None;
            }
            self.output.resize(capacity, 0);
        }
        let output = &mut self.output[..capacity];
        let produced = match encoding {
            Encoding::Brotli => brotli::decode(input, output, brotli::Window::Standard),
            Encoding::Gzip => gzip::decode(
                self.inflater.get_or_insert_with(Inflate::new),
                input,
                output,
            ),
            Encoding::Zlib | Encoding::Deflate => {
                let format = match encoding {
                    Encoding::Zlib => DeflateFormat::Zlib,
                    _ => DeflateFormat::Raw,
                };
                self.inflater
                    .get_or_insert_with(Inflate::new)
                    .inflate_member(format, input, output)
                    .ok()
                    .map(|progress| progress.produced)
            }
        };
        let Some(produced) = produced else {
            // A rejected member could already have filled its entire output window.
            self.remaining -= capacity;
            return None;
        };
        self.remaining -= produced.max(1);
        Some(&self.output[..produced])
    }
}
