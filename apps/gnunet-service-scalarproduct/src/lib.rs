//! ECC/Paillier Alice/Bob services over shared native process startup.
#![deny(unsafe_code)]
mod foreground;
mod lifecycle;
mod settings;
use gnunet_program_host::service::native::{self, Application, Context};
use std::{error::Error, marker::PhantomData, process::ExitCode};
type Cause = Box<dyn Error>;
#[derive(Clone, Copy)]
enum Mode {
    Alice,
    Bob,
    PaillierAlice,
    PaillierBob,
}
impl Mode {
    const fn profile_name(self) -> &'static str {
        match self {
            Self::Alice | Self::Bob => "ecc",
            Self::PaillierAlice | Self::PaillierBob => "paillier",
        }
    }
    fn profile(self) -> gnunet_scalarproduct_host::Profile {
        match self {
            Self::Alice | Self::Bob => gnunet_scalarproduct_host::Profile::Ecc,
            Self::PaillierAlice | Self::PaillierBob => {
                gnunet_scalarproduct_host::Profile::Paillier(
                    gnunet_scalarproduct_paillier::Limits::default(),
                )
            }
        }
    }
    const fn section(self) -> &'static [u8] {
        match self {
            Self::Alice | Self::PaillierAlice => b"scalarproduct-alice",
            Self::Bob | Self::PaillierBob => b"scalarproduct-bob",
        }
    }
    const fn binary(self) -> &'static str {
        match self {
            Self::Alice => "gnunet-service-scalarproduct-ecc-alice",
            Self::Bob => "gnunet-service-scalarproduct-ecc-bob",
            Self::PaillierAlice => "gnunet-service-scalarproduct-alice",
            Self::PaillierBob => "gnunet-service-scalarproduct-bob",
        }
    }
    const fn role(self) -> gnunet_scalarproduct_host::Role {
        match self {
            Self::Alice | Self::PaillierAlice => gnunet_scalarproduct_host::Role::Alice,
            Self::Bob | Self::PaillierBob => gnunet_scalarproduct_host::Role::Bob,
        }
    }
}
trait Variant {
    const MODE: Mode;
}
struct EccAlice;
struct EccBob;
struct PaillierAlice;
struct PaillierBob;
impl Variant for EccAlice {
    const MODE: Mode = Mode::Alice;
}
impl Variant for EccBob {
    const MODE: Mode = Mode::Bob;
}
impl Variant for PaillierAlice {
    const MODE: Mode = Mode::PaillierAlice;
}
impl Variant for PaillierBob {
    const MODE: Mode = Mode::PaillierBob;
}
struct Service<V>(PhantomData<V>);
impl<V: Variant> Application for Service<V> {
    const SECTION: &'static [u8] = V::MODE.section();
    const BINARY: &'static str = V::MODE.binary();
    type Settings = settings::Settings;
    fn settings(config: &gnunet_config::Configuration) -> Result<Self::Settings, Cause> {
        settings::Settings::read(config, V::MODE)
    }
    fn access(settings: &Self::Settings) -> gnunet_service_runtime::credentials::UnixAccess {
        settings.access
    }
    async fn serve(context: Context<'_, Self::Settings>) -> Result<(), Cause> {
        let cleanup = lifecycle::Cleanup::default();
        let result = foreground::run(foreground::Inputs {
            mode: V::MODE,
            config: context.config,
            settings: &context.settings,
            bound: context.listeners,
            signals: context.signals,
            clock: context.clock,
            reports: context.reports,
            notification: context.readiness,
            cleanup: cleanup.clone(),
        })
        .await;
        cleanup.finish(result)
    }
}
/// Enter the ordinary ECC Alice service executable.
///
/// # Safety
/// Call once as a fresh single-threaded executable's first operation, before
/// native resources, runtime, threads or environment mutation can compete.
#[expect(
    unsafe_code,
    reason = "Forwards unique fresh-process startup exactly once"
)]
pub unsafe fn alice_main() -> ExitCode {
    // SAFETY: the caller provides the unique fresh executable contract.
    unsafe { native::main::<Service<EccAlice>>() }
}
/// Enter the ordinary ECC Bob service executable.
///
/// # Safety
/// Call once as a fresh single-threaded executable's first operation, before
/// native resources, runtime, threads or environment mutation can compete.
#[expect(
    unsafe_code,
    reason = "Forwards unique fresh-process startup exactly once"
)]
pub unsafe fn bob_main() -> ExitCode {
    // SAFETY: the caller provides the unique fresh executable contract.
    unsafe { native::main::<Service<EccBob>>() }
}
/// Enter the ordinary Paillier Alice service executable.
///
/// # Safety
/// Call once as a fresh single-threaded executable's first operation, before
/// native resources, runtime, threads or environment mutation can compete.
#[expect(
    unsafe_code,
    reason = "Forwards unique fresh-process startup exactly once"
)]
pub unsafe fn paillier_alice_main() -> ExitCode {
    // SAFETY: the caller provides the unique fresh executable contract.
    unsafe { native::main::<Service<PaillierAlice>>() }
}
/// Enter the ordinary Paillier Bob service executable.
///
/// # Safety
/// Call once as a fresh single-threaded executable's first operation, before
/// native resources, runtime, threads or environment mutation can compete.
#[expect(
    unsafe_code,
    reason = "Forwards unique fresh-process startup exactly once"
)]
pub unsafe fn paillier_bob_main() -> ExitCode {
    // SAFETY: the caller provides the unique fresh executable contract.
    unsafe { native::main::<Service<PaillierBob>>() }
}
