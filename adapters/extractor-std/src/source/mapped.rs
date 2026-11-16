//! Windows original-file view input; no pathname or shared cursor is used.
use super::{Extraction, Failure, File, NativeError, Provider, SourceStamp};
use crate::PanicPayload;
use gnunet_native::filesystem::ReadMapping;
use std::panic::{AssertUnwindSafe, catch_unwind};
pub(super) fn extract<E>(
    provider: &mut Provider,
    file: &File,
    stamp: SourceStamp,
    guard: &mut impl FnMut() -> Result<(), E>,
) -> Result<Extraction, Failure<E>> {
    if stamp.bytes() > provider.limits().mapped_input_bytes {
        return Err(Failure::native(NativeError::Limit(
            "native mapped input extent",
        )));
    }
    guard().map_err(Failure::caller)?;
    let mut mapping = ReadMapping::open(file, stamp.bytes()).map_err(|source| {
        Failure::native(NativeError::Io {
            operation: "map original extraction source",
            source,
        })
    })?;
    let result = catch_unwind(AssertUnwindSafe(|| {
        guard().map_err(Failure::caller)?;
        if !stamp.verify(file).map_err(Failure::native)? {
            return Err(Failure::native(NativeError::SourceChanged));
        }
        provider.extract_mapping(&mapping, guard)
    }))
    .unwrap_or_else(|payload| {
        Err(Failure::native(NativeError::CallbackPanicked(
            PanicPayload(payload),
        )))
    });
    // Cleanup ignores expired business guards, preserving its independent error.
    match (result, mapping.close()) {
        (Ok(value), Ok(_)) => Ok(value),
        (Err(error), Ok(_)) => Err(error),
        (Ok(_), Err(source)) => Err(Failure::native(NativeError::Io {
            operation: "unmap original extraction source",
            source,
        })),
        (Err(mut error), Err(source)) => {
            error.cleanup = Some(NativeError::Io {
                operation: "unmap original extraction source",
                source,
            });
            Err(error)
        }
    }
}
