//! A saturated logical deadline is FOREVER, not immediately due.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Deadline assertions identify actual state changes"
)]
use gnunet_core::{
    session::{Event, Identity, Phase, Session},
    wire::WordOrder,
};
use gnunet_crypto::Entropy;
use gnunet_types::Error;
struct Random(u8);
impl Entropy for Random {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), Error> {
        bytes.fill(self.0);
        self.0 = self.0.wrapping_add(1);
        Ok(())
    }
}
#[test]
fn saturated_retransmit_and_liveness_targets_are_forever() -> Result<(), Error> {
    let a = Identity::from_seed([21; 32]);
    let b = Identity::from_seed([22; 32]);
    let mut aa = Session::<1024>::new(&a, b.public_key(), WordOrder::Little, b"")?;
    let mut bb = Session::<1024>::new(&b, a.public_key(), WordOrder::Little, b"")?;
    let (i, r) = if aa.phase() == Phase::Ready {
        (&mut aa, &mut bb)
    } else {
        (&mut bb, &mut aa)
    };
    let mut random = Random(19);
    let mut out = [0; 2048];
    let mut plain = [0; 2048];
    let Event::Send(n) = i.tick(u64::MAX, &mut random, &mut out)? else {
        return Err(Error::NotReady);
    };
    let ih = out[..n].to_vec();
    assert_eq!(i.next_deadline(), u64::MAX);
    assert_eq!(i.tick(u64::MAX, &mut random, &mut out)?, Event::None);
    let Event::Send(n) = r.receive(u64::MAX, &ih, &mut random, &mut out, &mut plain)? else {
        return Err(Error::NotReady);
    };
    let rh = out[..n].to_vec();
    assert_eq!(r.tick(u64::MAX, &mut random, &mut out)?, Event::None);
    let Event::Send(n) = i.receive(u64::MAX, &rh, &mut random, &mut out, &mut plain)? else {
        return Err(Error::NotReady);
    };
    let done = out[..n].to_vec();
    assert_eq!(i.tick(u64::MAX, &mut random, &mut out)?, Event::None);
    let Event::Established(n) = r.receive(u64::MAX, &done, &mut random, &mut out, &mut plain)?
    else {
        return Err(Error::NotReady);
    };
    let ack = out[..n].to_vec();
    assert_eq!(
        i.receive(u64::MAX, &ack, &mut random, &mut out, &mut plain)?,
        Event::Established(0)
    );
    assert_eq!(i.tick(u64::MAX, &mut random, &mut out)?, Event::None);
    assert_eq!(r.tick(u64::MAX, &mut random, &mut out)?, Event::None);
    assert!(i.established() && r.established());
    Ok(())
}
