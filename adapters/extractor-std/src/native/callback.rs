//! Bounded callback-to-owned-metadata bridge; no borrowed native pointer escapes.
use crate::{Extraction, Failure, Format, Item, Limits, NativeError, PanicPayload};
use std::{
    ffi::{c_char, c_int, c_void},
    panic::{AssertUnwindSafe, catch_unwind},
};
pub(super) struct Collector<'a, G, E> {
    guard: &'a mut G,
    limits: Limits,
    items: Vec<Item>,
    callbacks: usize,
    retained: usize,
    failure: Option<Failure<E>>,
}
impl<'a, G: FnMut() -> Result<(), E>, E> Collector<'a, G, E> {
    pub(super) fn new(limits: Limits, guard: &'a mut G) -> Result<Self, NativeError> {
        let mut items = Vec::new();
        items
            .try_reserve_exact(limits.items)
            .map_err(|_| NativeError::Limit("metadata record allocation"))?;
        let retained = items
            .capacity()
            .checked_mul(std::mem::size_of::<Item>())
            .filter(|n| *n <= limits.output_bytes)
            .ok_or(NativeError::Limit("metadata record actual capacity"))?;
        Ok(Self {
            guard,
            limits,
            items,
            callbacks: 0,
            retained,
            failure: None,
        })
    }
    pub(super) fn check(&mut self) -> Result<(), Failure<E>> {
        (self.guard)().map_err(Failure::caller)
    }
    pub(super) fn finish(mut self) -> Result<Extraction, Failure<E>> {
        if let Some(error) = self.failure.take() {
            return Err(error);
        }
        self.check()?;
        Ok(Extraction {
            items: self.items,
            callbacks: self.callbacks,
            retained: self.retained,
        })
    }
    fn push(
        &mut self,
        kind: c_int,
        format: c_int,
        plugin: Option<&[u8]>,
        mime: Option<&[u8]>,
        data: &[u8],
    ) -> Result<(), NativeError> {
        self.callbacks = self
            .callbacks
            .checked_add(1)
            .filter(|n| *n <= self.limits.callbacks)
            .ok_or(NativeError::Limit("metadata callbacks"))?;
        if self.items.len() >= self.limits.items || data.len() > self.limits.value_bytes {
            return Err(NativeError::Limit("metadata item/data extent"));
        }
        let kind =
            u32::try_from(kind).map_err(|_| NativeError::Invalid("negative metadata type"))?;
        let format = match format {
            1 => Format::Utf8,
            2 => Format::Binary,
            3 => Format::CString,
            _ => return Err(NativeError::Invalid("metadata format")),
        };
        let append = format != Format::Binary && data.last() != Some(&0);
        let item = Item {
            kind,
            format,
            plugin: plugin.map(|p| copy(p, false)).transpose()?,
            mime: mime.map(|m| copy(m, false)).transpose()?,
            data: copy(data, append)?,
        };
        let retained = self
            .retained
            .checked_add(
                item.retained()
                    .ok_or(NativeError::Limit("metadata arithmetic"))?,
            )
            .filter(|n| *n <= self.limits.output_bytes)
            .ok_or(NativeError::Limit("metadata actual retained capacity"))?;
        self.items.push(item);
        self.retained = retained;
        Ok(())
    }
}
fn copy(bytes: &[u8], append: bool) -> Result<Vec<u8>, NativeError> {
    let n = bytes
        .len()
        .checked_add(usize::from(append))
        .ok_or(NativeError::Limit("metadata copy extent"))?;
    let mut out = Vec::new();
    out.try_reserve_exact(n)
        .map_err(|_| NativeError::Limit("metadata payload allocation"))?;
    out.extend_from_slice(bytes);
    if append {
        out.push(0);
    }
    Ok(out)
}
unsafe fn name<'a>(raw: *const c_char, bound: usize) -> Result<Option<&'a [u8]>, NativeError> {
    if raw.is_null() {
        return Ok(None);
    }
    // SAFETY: libextractor's callback ABI supplies a valid NUL-terminated name.
    // The scan stops at that NUL and no unbounded CStr scan is used.
    let mut n = 0;
    // SAFETY: inspect only the original string through its first NUL; no Rust
    // slice is fabricated for bytes beyond a possibly shorter native string.
    while n <= bound && unsafe { raw.add(n).read() } != 0 {
        n += 1;
    }
    if n > bound {
        return Err(NativeError::Limit("metadata name"));
    }
    // SAFETY: n bytes and its NUL are within the original callback string.
    Ok(Some(unsafe {
        std::slice::from_raw_parts(raw.cast(), n + 1)
    }))
}
pub(super) unsafe extern "C" fn receive<G: FnMut() -> Result<(), E>, E>(
    cls: *mut c_void,
    plugin: *const c_char,
    kind: c_int,
    format: c_int,
    mime: *const c_char,
    data: *const c_char,
    len: usize,
) -> c_int {
    // SAFETY: run passes this exact live stack collector for one synchronous
    // IN_PROCESS extraction. Native pointers are borrowed only inside this call.
    let state = unsafe { &mut *cls.cast::<Collector<'_, G, E>>() };
    if state.failure.is_some() {
        return 1;
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        state.check()?;
        if len > state.limits.value_bytes {
            return Err(Failure::native(NativeError::Limit(
                "metadata callback data extent",
            )));
        }
        if data.is_null() && len != 0 {
            return Err(Failure::native(NativeError::Invalid(
                "metadata callback data extent",
            )));
        }
        // SAFETY: native ABI guarantees exactly len readable original bytes;
        // policy checks precede constructing a slice. NULL/zero is handled.
        let data = if len == 0 {
            &[]
        } else {
            // SAFETY: the checked non-null ABI pointer has len readable bytes.
            unsafe { std::slice::from_raw_parts(data.cast(), len) }
        };
        // SAFETY: original callback names are live terminated ABI strings.
        let plugin = unsafe { name(plugin, state.limits.name_bytes) }.map_err(Failure::native)?;
        // SAFETY: same callback ABI, with NULL preserving an absent MIME.
        let mime = unsafe { name(mime, state.limits.name_bytes) }.map_err(Failure::native)?;
        state
            .push(kind, format, plugin, mime, data)
            .map_err(Failure::native)?;
        state.check()
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(error)) => {
            state.failure = Some(error);
            1
        }
        Err(payload) => {
            state.failure = Some(Failure::native(NativeError::CallbackPanicked(
                PanicPayload(payload),
            )));
            1
        }
    }
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Pure callback-format/resource assertions preserve native setup failures"
)]
mod tests {
    use super::*;
    use crate::Selection;
    use std::convert::Infallible;

    #[test]
    fn native_record_formats_keep_binary_zero_and_terminate_text() -> Result<(), NativeError> {
        let mut guard = || Ok::<(), Infallible>(());
        let mut records = Collector::new(Limits::default(), &mut guard)?;
        // These are extractor.h's actual public values, not renamed private
        // format IDs. Empty binary is valid; empty text still needs its NUL.
        records.push(4, 1, Some(b"title\0"), Some(b"text/plain\0"), b"title")?;
        records.push(45, 2, None, None, b"")?;
        records.push(13, 3, Some(b"legacy\0"), None, b"")?;
        assert_eq!(records.items[0].data, b"title\0");
        assert_eq!(records.items[1].format, Format::Binary);
        assert!(records.items[1].data.is_empty());
        assert_eq!(records.items[2].data, b"\0");
        assert_eq!(
            records.items[0].plugin.as_deref(),
            Some(b"title\0".as_slice())
        );
        assert_eq!(
            records.items[0].mime.as_deref(),
            Some(b"text/plain\0".as_slice())
        );
        Ok(())
    }

    #[test]
    fn own_limit_or_original_stop_never_returns_empty_observation() -> Result<(), NativeError> {
        let mut guard = || Err::<(), _>(17u32);
        let limits = Limits {
            items: 2,
            value_bytes: 4,
            ..Limits::default()
        };
        let mut records = Collector::new(limits, &mut guard)?;
        assert!(matches!(
            records.check(),
            Err(Failure {
                cause: crate::Cause::Caller(17),
                ..
            })
        ));
        records.push(4, 1, None, None, b"abc")?;
        let retained = records.retained;
        assert!(matches!(
            records.push(1, 2, None, None, b"too long"),
            Err(NativeError::Limit(_))
        ));
        assert_eq!(records.items.len(), 1);
        assert_eq!(records.retained, retained);
        assert!(matches!(
            Selection::from_fs(false, Some(b"-")),
            Selection::Disabled
        ));
        assert!(matches!(
            Selection::from_fs(false, Some(b"-mime:png")),
            Selection::DefaultsWith(b"-mime:png")
        ));
        Ok(())
    }
}
