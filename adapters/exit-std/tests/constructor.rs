//! Constructor origin admission only; no driver poll, socket or device access.
#![expect(
    clippy::panic_in_result_fn,
    reason = "One original public lifecycle verifies refusal preserves the retained quarantine and owners"
)]
use gnunet_cadet_host as cadet;
use gnunet_exit::{
    AfProfile,
    engine::{Config, Engine, Limits as CoreLimits, Target},
    policy::{InternetRules, Policy},
};
use gnunet_exit_host::runtime::{Driver, Error, Limits, OsEntropy, Parts};
use gnunet_types::{Error as Fault, MonoInstant};

#[test]
fn quiescent_engine_with_original_quarantine_cannot_bind_a_new_epoch()
-> Result<(), Box<dyn std::error::Error>> {
    let limits = CoreLimits::default();
    let mut engine = Engine::new(
        Config {
            policy: Policy {
                ipv4: false,
                ipv6: false,
                rules: InternetRules::Ordered {
                    rules: &[],
                    default_allow: false,
                },
            },
            ipv4: None,
            ipv6: None,
            services: &[],
            dns: true,
            af: AfProfile::native(),
        },
        limits,
    )?;
    assert!(engine.is_pristine());
    let source = engine.attached()?;
    let flow = engine.accept(&source, [7; 32], Target::Dns, MonoInstant(0))?;
    engine.source_lost(&source)?;
    engine.advance(MonoInstant(0))?;
    assert_eq!(engine.next_closed().ok_or(Fault::NotReady)?.flow, flow);
    assert!(engine.is_quiescent());
    assert!(!engine.is_pristine());
    let original = Some(MonoInstant(limits.quarantine));
    assert_eq!(engine.next_deadline(), original);

    let mut instance = cadet::Instance::new();
    let mut ports = [cadet::PortSlot::new(); 1];
    let mut channels = [cadet::ChannelSlot::new(); 1];
    // CLIENT construction subscribes to the source but never connects; the
    // constructor refusal must precede timers, source attachment and entropy.
    let native = cadet::Client::new(
        &mut instance,
        cadet::EndpointSource::unix("/unopened-exit-constructor-cadet.sock".into()),
        &mut ports,
        &mut channels,
        cadet::Limits::default(),
    )?;
    let Err(mut failure) = Driver::try_new(
        Parts {
            engine,
            cadet: native,
            tun: None,
            entropy: OsEntropy::default(),
        },
        &[],
        None,
        Limits::default(),
    ) else {
        return Err("used EXIT engine acquired a replacement native epoch".into());
    };
    assert!(matches!(failure.error, Error::Core(Fault::Conflict)));
    assert_eq!(failure.parts.engine.next_deadline(), original);
    assert!(failure.parts.engine.next_closed().is_none());
    assert!(failure.parts.cadet.epoch().is_none());
    assert!(failure.parts.cadet.pending_transmit().is_none());
    assert!(failure.parts.cadet.close()?.is_none());
    Ok(())
}
