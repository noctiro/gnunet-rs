//! WDK boundary for the Windows DNS interception callouts.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn, missing_docs)]

#[cfg(not(all(
    target_os = "windows",
    target_env = "msvc",
    any(target_arch = "x86_64", target_arch = "aarch64"),
)))]
compile_error!("this WDK driver requires a Windows MSVC x64 or ARM64 target");

// PE machine identifiers. Check the generated ABI used the same target as rustc.
#[cfg(target_arch = "x86_64")]
const _: () = assert!(
    sdk::GNUNET_WFP_ABI_MACHINE == 0x8664,
    "expected AMD64 WDK bindings"
);
#[cfg(target_arch = "aarch64")]
const _: () = assert!(
    sdk::GNUNET_WFP_ABI_MACHINE == 0xAA64,
    "expected ARM64 WDK bindings"
);

const POOL_ALIGNMENT: usize = sdk::GNUNET_WFP_POOL_ALIGNMENT as usize;

pub mod callbacks;
pub mod capture;
pub mod device;
pub mod driver;
pub mod flow;
mod ids;
pub mod inject;
pub mod lock;
mod path;
pub mod policy;
mod receive;
pub mod registration;
pub mod runtime;
pub mod transport;
pub use receive::{Classify, Verdict, inspect};

/// ABI generated from the selected SDK by the repository's WDK bindings tool.
#[allow(clippy::all, reason = "Generated WDK ABI, including bindgen bitfields")]
#[allow(
    dead_code,
    improper_ctypes,
    missing_docs,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unnecessary_transmutes
)]
pub mod sdk {
    include!(env!("GNUNET_WDK_BINDINGS"));
}
