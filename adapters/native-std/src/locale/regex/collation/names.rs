//! Exact NLS-name to ICU identity conversion and retained sort verification.
use super::{super::nls, api::Api};
use std::{ffi::c_char, io};
impl Api {
    pub fn locale_id(&self, name: &nls::Name) -> io::Result<std::ffi::CString> {
        let name_units = name.units();
        if name_units.is_empty() {
            return ascii_string(b"root");
        }
        let mut tag = Vec::new();
        tag.try_reserve_exact(name_units.len())
            .map_err(|_| io::ErrorKind::OutOfMemory)?;
        for unit in name_units {
            tag.push(u8::try_from(*unit).map_err(|_| io::ErrorKind::InvalidData)?);
        }
        let alternate = tag.contains(&b'_');
        let tag = ascii_string(&tag)?;
        let mut output = [0; 256];
        let mut status = 0;
        let mut parsed = 0;
        #[expect(
            unsafe_code,
            reason = "Validated terminated locale names and exclusive fixed-capacity scalar/string outputs remain live; neither ICU converter installs locale state"
        )]
        let count = if alternate {
            let id = nls::automation_id(name)?;
            // SAFETY: exact native LCID and fixed output extent match the C API.
            unsafe {
                (self.windows_locale)(id, output.as_mut_ptr(), output.len() as i32, &mut status)
            }
        } else {
            // SAFETY: terminated tag and all initialized exclusive outputs stay live.
            unsafe {
                (self.language)(
                    tag.as_ptr(),
                    output.as_mut_ptr(),
                    output.len() as i32,
                    &mut parsed,
                    &mut status,
                )
            }
        };
        super::check("ICU locale conversion", status)?;
        if !alternate && usize::try_from(parsed).ok() != Some(tag.as_bytes().len()) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ICU did not retain the complete selected locale name",
            ));
        }
        let value = string(&output, count)?;
        if value.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "ICU has no selected collation locale",
            ));
        }
        Ok(value)
    }
    #[expect(
        unsafe_code,
        reason = "A terminated ICU locale ID and exclusive fixed output storage satisfy the synchronous likely-subtag API"
    )]
    pub fn expanded(&self, locale: &std::ffi::CStr) -> io::Result<std::ffi::CString> {
        let mut canonical = [0; 256];
        let mut status = 0;
        // SAFETY: original terminated name and exclusive fixed canonical output.
        let count = unsafe {
            (self.canonical)(
                locale.as_ptr(),
                canonical.as_mut_ptr(),
                canonical.len() as i32,
                &mut status,
            )
        };
        super::check("uloc_canonicalize", status)?;
        let canonical = string(&canonical, count)?;
        let mut output = [0; 256];
        let mut status = 0;
        // SAFETY: original terminated name and initialized bounded output/status.
        let count = unsafe {
            (self.likely)(
                canonical.as_ptr(),
                output.as_mut_ptr(),
                output.len() as i32,
                &mut status,
            )
        };
        super::check("uloc_addLikelySubtags", status)?;
        string(&output, count)
    }
    #[expect(
        unsafe_code,
        reason = "The terminated selected locale and fixed output buffer stay borrowed throughout one synchronous ICU keyword lookup"
    )]
    pub fn sort_keyword(&self, locale: &std::ffi::CStr) -> io::Result<std::ffi::CString> {
        let mut output = [0; 128];
        let mut status = 0;
        // SAFETY: terminated strings and an initialized exclusive output extent.
        let count = unsafe {
            (self.keyword)(
                locale.as_ptr(),
                c"collation".as_ptr(),
                output.as_mut_ptr(),
                output.len() as i32,
                &mut status,
            )
        };
        super::check("ICU collation keyword", status)?;
        string(&output, count)
    }
}
fn string(bytes: &[c_char], count: i32) -> io::Result<std::ffi::CString> {
    let count = usize::try_from(count).map_err(|_| io::ErrorKind::InvalidData)?;
    if bytes.get(count) != Some(&0) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(count + 1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    for unit in &bytes[..count] {
        owned.push(*unit as u8);
    }
    owned.push(0);
    std::ffi::CString::from_vec_with_nul(owned).map_err(|_| io::ErrorKind::InvalidData.into())
}
fn ascii_string(bytes: &[u8]) -> io::Result<std::ffi::CString> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len() + 1)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    owned.extend_from_slice(bytes);
    owned.push(0);
    std::ffi::CString::from_vec_with_nul(owned).map_err(|_| io::ErrorKind::InvalidData.into())
}
