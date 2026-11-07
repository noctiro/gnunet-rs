//! One pure packed-inner debt model; write/ACK callbacks are explicit premises,
//! not executed TUN/CADET/native interoperability or a device simulation.
#![cfg(feature = "alloc")]
#![expect(
    clippy::panic_in_result_fn,
    reason = "One focused model checks packed receipt scope and atomic bounded refusal"
)]
use gnunet_exit::{
    Address, AfProfile, Family,
    engine::{Config, Effect, Engine, Limits, Target},
    nat::{Entropy, Pool},
    policy::{Policy, Prefix},
};
use gnunet_types::{Error, MonoInstant};
use gnunet_wire::official::vpn::PeerMessage;
struct ModelEntropy(u8);
impl Entropy for ModelEntropy {
    fn fill(&mut self, b: &mut [u8]) -> Result<(), Error> {
        for v in b {
            self.0 = self.0.wrapping_add(17);
            *v = self.0;
        }
        Ok(())
    }
}
fn message() -> Result<Vec<u8>, Error> {
    let m = PeerMessage::UdpInternet {
        address: Address::V4([203, 0, 113, 9]),
        source: 0,
        destination: 53,
        payload: b"data",
    };
    let mut b = vec![0; m.encoded_len()?];
    m.encode_with_profile(&mut b, AfProfile::LINUX)?;
    Ok(b)
}
#[test]
fn packed_inner_ready_is_not_outer_ack_and_capacity_preserves_original() -> Result<(), Error> {
    let config = Config {
        policy: Policy {
            ipv4: true,
            ipv6: false,
            rules: gnunet_exit::policy::InternetRules::Ordered {
                rules: &[],
                default_allow: true,
            },
        },
        ipv4: Some(Pool {
            subnet: Prefix {
                address: Address::V4([10, 23, 0, 1]),
                bits: 24,
            },
        }),
        ipv6: None,
        services: &[],
        dns: false,
        af: AfProfile::LINUX,
    };
    let mut engine = Engine::new(
        config,
        Limits {
            processing_receipts: 2,
            ..Limits::default()
        },
    )?;
    let source = engine.attached()?;
    let tun = engine.tun_attached()?;
    let flow = engine.accept(
        &source,
        [7; 32],
        Target::Internet(Family::V4),
        MonoInstant(1),
    )?;
    let mut entropy = ModelEntropy(1);
    let data = message()?;
    let first = engine.receive(&flow, &data, MonoInstant(2), &mut entropy)?;
    let output = engine.tun_output().ok_or(Error::NotReady)?;
    let write = output.write;
    engine.tun_written(&tun, &write)?;
    let Some(Effect::Processed { input, .. }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(input, first);
    engine.processing_batched(&input)?;
    // No native outer ACK has happened. A second inner frame can nevertheless
    // enter the same original flow after the first real forwarding write.
    let second = engine.receive(&flow, &data, MonoInstant(3), &mut entropy)?;
    let write = engine.tun_output().ok_or(Error::NotReady)?.write;
    engine.tun_written(&tun, &write)?;
    let Some(Effect::Processed { input, .. }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(input, second);
    engine.processing_batched(&input)?;
    let other = engine.accept(
        &source,
        [8; 32],
        Target::Internet(Family::V4),
        MonoInstant(4),
    )?;
    let third = engine.receive(&other, &data, MonoInstant(5), &mut entropy)?;
    let write = engine.tun_output().ok_or(Error::NotReady)?.write;
    engine.tun_written(&tun, &write)?;
    let Some(Effect::Processed { input, .. }) = engine.effect() else {
        return Err(Error::NotReady);
    };
    assert_eq!(input, third);
    assert_eq!(engine.processing_batched(&third), Err(Error::WouldBlock));
    // This is the model's exact original outer ACK Written boundary. Merely
    // taking Processed/batching above did not settle either original receipt.
    engine.acknowledged(&first)?;
    engine.acknowledged(&second)?;
    assert_eq!(engine.acknowledged(&first), Err(Error::Stale));
    engine.processing_batched(&third)?;
    engine.close(&other)?;
    engine.closed(&other)?;
    assert!(engine.next_closed().is_none());
    // An actual original source loss settles retained ACK debt without inventing
    // an ACK or transferring it to a new attachment/channel generation.
    engine.source_lost(&source)?;
    engine.tun_lost(&tun, None)?;
    assert!(engine.is_quiescent());
    assert_eq!(engine.acknowledged(&third), Err(Error::Stale));
    Ok(())
}
