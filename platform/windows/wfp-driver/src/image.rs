//! Native entry for the WDM driver image.
#![no_std]

use core::panic::PanicInfo;
use gnunet_wfp_driver::{driver, sdk};

const _: sdk::PDRIVER_INITIALIZE = Some(DriverEntry);

/// Initialize this WDM driver with the I/O manager's original objects.
///
/// # Safety
/// Call once from the WDK entry wrapper with its original arguments at
/// `PASSIVE_LEVEL`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn DriverEntry(
    object: *mut sdk::DRIVER_OBJECT,
    registry: *mut sdk::UNICODE_STRING,
) -> sdk::NTSTATUS {
    // SAFETY: this forwards the exact native entry arguments unchanged.
    unsafe { driver::entry(object, registry) }
}

#[panic_handler]
fn panic(info: &PanicInfo<'_>) -> ! {
    let (line, column) = info
        .location()
        .map_or((0, 0), |loc| (loc.line(), loc.column()));
    // An unexpected kernel invariant failure cannot unwind across WDK or resume
    // after a partial state transition. Keep the source location in the dump.
    // SAFETY: the SDK accepts this terminal call at any IRQL.
    unsafe {
        sdk::KeBugCheckEx(
            sdk::GNUNET_WFP_DRIVER_VIOLATION.cast_unsigned(),
            u64::from(u32::from_le_bytes(*b"GNDN")),
            u64::from(line),
            u64::from(column),
            0,
        )
    }
}
