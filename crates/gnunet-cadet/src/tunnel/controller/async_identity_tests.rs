//! Trusted-provider ownership models with real local ECDH, not C interoperability evidence.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible async KX models assert exact source/epoch/candidate ownership, real DH and original retirement"
)]
use super::*;
use crate::{
    connection::{FrameSlot, Instance, NeighborSlot, RouteSlot},
    tunnel::{
        SkippedSlot,
        identity_dh::{Completion, Port, Request, Source},
    },
};
use gnunet_session_crypto::exchange::{EcdhePublic, EcdheSecret};
const PLAIN: [u8; 4] = [0, 4, 3, 244];
struct Draw(u8);
impl Entropy for Draw {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        output.fill(self.0);
        self.0 = self.0.checked_add(1).ok_or(Error::Entropy)?;
        Ok(())
    }
}
struct ModelPort<'id> {
    source: Source<'id>,
    identity: &'id Identity,
    pending: Option<Request<'id>>,
    ready: bool,
    retirement_ready: bool,
    submitted: usize,
    finished: usize,
}
impl<'id> Port<'id> for ModelPort<'id> {
    fn source(&self) -> Source<'id> {
        self.source
    }
    fn submit(&mut self, request: Request<'id>) -> Result<(), Error> {
        if request.source() != self.source || request.source().local() != self.identity.peer() {
            return Err(Error::StaleGeneration);
        }
        if self.pending.is_some() {
            return Err(Error::Conflict);
        }
        self.pending = Some(request);
        self.submitted += 1;
        Ok(())
    }
    fn finish<T>(
        &mut self,
        request: Request<'id>,
        accept: impl FnOnce(&[u8; 64]) -> Result<T, Error>,
    ) -> Result<Completion<T>, Error> {
        if self.pending != Some(request) {
            return Err(Error::StaleGeneration);
        }
        if !self.ready {
            return Ok(Completion::Pending);
        }
        self.pending = None;
        self.finished += 1;
        // Same exact SHA512(identity-private × original peer ephemeral) supplied
        // by standard PILS; the test provider actually computes it locally.
        let hash = self
            .identity
            .dh
            .exchange_hashed(EcdhePublic::from_bytes(
                request.remote_exchange().ephemeral_key,
            ))?
            .into_secret_bytes();
        Ok(Completion::Finished(accept(&hash)))
    }
    fn retire(&mut self, request: Request<'id>) -> Result<bool, Error> {
        if self.pending != Some(request) {
            return Err(Error::StaleGeneration);
        }
        if !self.retirement_ready {
            return Ok(false);
        }
        self.pending = None;
        Ok(true)
    }
}
fn fixture(
    test: impl for<'id, 'slots, 'route> FnOnce(
        &mut Controller<'id, 'slots, 'route>,
        &mut Controller<'id, 'slots, 'route>,
        &mut ModelPort<'id>,
        &mut ModelPort<'id>,
        &mut Draw,
    ) -> Result<(), Error>,
) -> Result<(), Error> {
    let first = Identity::from_seed([1; 32]);
    let second = Identity::from_seed([2; 32]);
    let (a, b) = if first.peer() < second.peer() {
        (first, second)
    } else {
        (second, first)
    };
    let domain = crate::tunnel::context::Instance::new();
    let mut context_rows = [const { crate::tunnel::context::Slot::new() }; 2];
    let mut registry = crate::tunnel::context::Registry::new(&domain, &mut context_rows)?;
    let ac = registry.allocate(a.peer(), b.peer())?;
    let bc = registry.allocate(b.peer(), a.peer())?;
    let source_domain = identity_dh::Instance::new();
    let mut source_rows = [const { identity_dh::Slot::new() }; 2];
    let mut sources = identity_dh::Registry::new(&source_domain, &mut source_rows)?;
    // Owned bindings remain alive through the two controllers and provider jobs.
    let a_binding = sources.bind(a.peer(), 7)?;
    let b_binding = sources.bind(b.peer(), 9)?;
    let asource = a_binding.source();
    let bsource = b_binding.source();
    let mut ai = Instance::new();
    let mut bi = Instance::new();
    let mut an = [NeighborSlot::new(); 1];
    let mut bn = [NeighborSlot::new(); 1];
    let mut ar = [RouteSlot::<2>::new(); 1];
    let mut br = [RouteSlot::<2>::new(); 1];
    let mut ao = [];
    let mut bo = [];
    let mut ab = [0; 256];
    let mut bb = [0; 256];
    let mut af = [FrameSlot::new(&mut ab)];
    let mut bf = [FrameSlot::new(&mut bb)];
    let abook = Book::new(
        &mut ai,
        a.peer(),
        &mut an,
        &mut ar,
        &mut ao,
        &mut af,
        MonoInstant(0),
        connection::Limits::default(),
    )?;
    let bbook = Book::new(
        &mut bi,
        b.peer(),
        &mut bn,
        &mut br,
        &mut bo,
        &mut bf,
        MonoInstant(0),
        connection::Limits::default(),
    )?;
    let mut as1 = [const { SkippedSlot::new() }; 2];
    let mut at1 = [const { SkippedSlot::new() }; 2];
    let mut as2 = [const { SkippedSlot::new() }; 2];
    let mut at2 = [const { SkippedSlot::new() }; 2];
    let mut bs1 = [const { SkippedSlot::new() }; 2];
    let mut bt1 = [const { SkippedSlot::new() }; 2];
    let mut bs2 = [const { SkippedSlot::new() }; 2];
    let mut bt2 = [const { SkippedSlot::new() }; 2];
    let limits = Limits {
        crypto: CryptoLimits {
            plaintext_bytes: 256,
            maximum_gap: 256,
        },
        negotiation_micros: 100,
        ..Limits::default()
    };
    let mut a_controller = Controller::new_external_identity(
        ac,
        asource,
        abook.reset_authority(),
        Stores {
            first: Storage {
                skipped: &mut as1,
                staging: &mut at1,
            },
            second: Storage {
                skipped: &mut as2,
                staging: &mut at2,
            },
        },
        limits,
        MonoInstant(0),
    )?;
    let mut b_controller = Controller::new_external_identity(
        bc,
        bsource,
        bbook.reset_authority(),
        Stores {
            first: Storage {
                skipped: &mut bs1,
                staging: &mut bt1,
            },
            second: Storage {
                skipped: &mut bs2,
                staging: &mut bt2,
            },
        },
        limits,
        MonoInstant(0),
    )?;
    let mut ap = ModelPort {
        source: asource,
        identity: &a,
        pending: None,
        ready: false,
        retirement_ready: true,
        submitted: 0,
        finished: 0,
    };
    let mut bp = ModelPort {
        source: bsource,
        identity: &b,
        pending: None,
        ready: false,
        retirement_ready: true,
        submitted: 0,
        finished: 0,
    };
    test(
        &mut a_controller,
        &mut b_controller,
        &mut ap,
        &mut bp,
        &mut Draw(17),
    )
}
fn begin<'id>(
    a: &mut Controller<'id, '_, '_>,
    b: &mut Controller<'id, '_, '_>,
    bp: &mut ModelPort<'id>,
    draw: &mut Draw,
) -> Result<(Exchange, [u8; 64]), Error> {
    assert!(matches!(
        a.request(a.scope(), MonoInstant(0), draw)?,
        Event::Started(_)
    ));
    let Some(Candidate::Alice { exchange, .. }) = a.candidate.as_ref() else {
        return Err(Error::NotReady);
    };
    assert!(matches!(b.kx(*exchange, draw)?, Event::AwaitIdentityDh(_)));
    assert!(b.intent.is_none());
    assert!(matches!(
        b.advance_identity_dh(b.scope(), bp, MonoInstant(0))?,
        Event::IdentityDhSubmitted(_)
    ));
    assert_eq!(
        b.advance_identity_dh(b.scope(), bp, MonoInstant(0))?,
        Event::Idle
    );
    bp.ready = true;
    assert!(matches!(
        b.advance_identity_dh(b.scope(), bp, MonoInstant(0))?,
        Event::Candidate(_)
    ));
    let Some(Candidate::Betty { live, .. }) = b.candidate.as_ref() else {
        return Err(Error::NotReady);
    };
    Ok((live.session.local_exchange, live.session.initial_proof))
}
fn confirm_betty(
    b: &mut Controller<'_, '_, '_>,
    a: &Controller<'_, '_, '_>,
    draw: &mut Draw,
) -> Result<(), Error> {
    let active = a.active.as_ref().ok_or(Error::NotReady)?;
    assert!(matches!(
        b.authentication(
            active.session.local_exchange,
            &active.session.initial_proof,
            false,
            draw
        )?,
        Event::Confirmed(_)
    ));
    Ok(())
}
fn handshake<'id>(
    a: &mut Controller<'id, '_, '_>,
    b: &mut Controller<'id, '_, '_>,
    ap: &mut ModelPort<'id>,
    bp: &mut ModelPort<'id>,
    draw: &mut Draw,
) -> Result<(), Error> {
    let (remote, proof) = begin(a, b, bp, draw)?;
    assert!(matches!(
        a.authentication(remote, &proof, true, draw)?,
        Event::AwaitIdentityDh(_)
    ));
    assert!(matches!(
        a.advance_identity_dh(a.scope(), ap, MonoInstant(0))?,
        Event::IdentityDhSubmitted(_)
    ));
    ap.ready = true;
    assert!(matches!(
        a.advance_identity_dh(a.scope(), ap, MonoInstant(0))?,
        Event::Confirmed(_)
    ));
    confirm_betty(b, a, draw)
}
#[test]
fn async_original_hash_matches_direct_schedule_for_both_roles_once() -> Result<(), Error> {
    fixture(|a, b, ap, bp, draw| {
        handshake(a, b, ap, bp, draw)?;
        let al = a.active.as_ref().ok_or(Error::NotReady)?;
        let bl = b.active.as_ref().ok_or(Error::NotReady)?;
        let ak = LocalKeys {
            ephemeral: EcdheSecret::from_bytes([17; 32]),
            ratchet: EcdheSecret::from_bytes([18; 32]),
        };
        let bk = LocalKeys {
            ephemeral: EcdheSecret::from_bytes([19; 32]),
            ratchet: EcdheSecret::from_bytes([20; 32]),
        };
        let adirect =
            Session::candidate_keys(a.scope(), ap.identity, &ak, al.session.remote_exchange)?;
        let bdirect =
            Session::candidate_keys(b.scope(), bp.identity, &bk, bl.session.remote_exchange)?;
        assert_eq!(al.session.keys.root.as_ref(), adirect.keys.root.as_ref());
        assert_eq!(bl.session.keys.root.as_ref(), bdirect.keys.root.as_ref());
        assert_eq!(al.session.keys.root.as_ref(), bl.session.keys.root.as_ref());
        assert_eq!(
            (ap.submitted, ap.finished, bp.submitted, bp.finished),
            (1, 1, 1, 1)
        );
        let snapshot = a.crypto_snapshot();
        assert_eq!(
            a.advance_identity_dh(a.scope(), ap, MonoInstant(0))?,
            Event::Idle
        );
        assert_eq!(a.crypto_snapshot(), snapshot);
        Ok(())
    })
}
#[test]
fn original_expiry_retains_real_retirement_and_old_confirmed_flow() -> Result<(), Error> {
    fixture(|a, b, ap, bp, draw| {
        handshake(a, b, ap, bp, draw)?;
        let confirmed = a.snapshot().confirmed;
        assert!(matches!(
            a.request(a.scope(), MonoInstant(1), draw)?,
            Event::Started(_)
        ));
        let remote = LocalKeys::generate(draw)?.exchange();
        assert!(matches!(
            a.authentication(remote, &[0x91; 64], true, draw)?,
            Event::AwaitIdentityDh(_)
        ));
        let request = a.pending_identity_dh().ok_or(Error::NotReady)?;
        assert_eq!(request.expires(), MonoInstant(101));
        let candidate = a.snapshot().candidate;
        assert_eq!(
            a.advance_identity_dh(a.scope(), bp, MonoInstant(90)),
            Err(Error::StaleGeneration)
        );
        assert_eq!(a.last_now, MonoInstant(1));
        assert_eq!(a.snapshot().candidate, candidate);
        ap.ready = false;
        ap.retirement_ready = false;
        assert!(matches!(
            a.advance_identity_dh(a.scope(), ap, MonoInstant(1))?,
            Event::IdentityDhSubmitted(_)
        ));
        assert_eq!(
            a.authentication(remote, &[0x91; 64], true, draw)?,
            Event::Duplicate
        );
        assert_eq!(ap.submitted, 2);
        let mut wire = [0; 256];
        let mut plain = [0; 16];
        let active = a.active.as_mut().ok_or(Error::NotReady)?;
        let sealed =
            active
                .session
                .seal(active.session.scope(), [9; 32], &PLAIN, &mut wire, draw)?;
        let peer = b.active.as_mut().ok_or(Error::NotReady)?;
        assert_eq!(
            peer.session
                .open(peer.session.scope(), sealed.bytes(), &mut plain)?
                .bytes(),
            PLAIN
        );
        let after = a.crypto_snapshot();
        ap.ready = true; // The original result is now late; it must never apply.
        assert_eq!(
            a.advance_identity_dh(a.scope(), ap, MonoInstant(101))?,
            Event::IdentityDhRetiring
        );
        assert!(a.snapshot().candidate.is_none());
        assert_eq!(a.snapshot().confirmed, confirmed);
        assert_eq!(a.crypto_snapshot(), after);
        assert_eq!(a.pending_identity_dh(), Some(request));
        assert_eq!(
            a.request(a.scope(), MonoInstant(102), draw)?,
            Event::CandidateBusy
        );
        assert_eq!(ap.finished, 1);
        ap.retirement_ready = true;
        assert_eq!(
            a.retire_identity_dh(a.scope(), ap)?,
            Event::IdentityDhRetired
        );
        assert!(a.pending_identity_dh().is_none());
        let mut called = false;
        let late = ap.finish(request, |_| {
            called = true;
            Ok(())
        });
        assert!(matches!(late, Err(Error::StaleGeneration)));
        assert!(!called);
        assert_eq!(a.crypto_snapshot(), after);
        assert_eq!(
            a.rebind_identity_source(a.scope(), bp.source()),
            Err(Error::Authentication)
        );
        a.rebind_identity_source(a.scope(), ap.source())?;
        assert_eq!(a.snapshot().confirmed, confirmed);
        assert_eq!(a.crypto_snapshot(), after);
        Ok(())
    })
}
#[test]
fn bad_original_auth_uses_one_dh_and_correct_proof_never_resets_epoch() -> Result<(), Error> {
    fixture(|a, b, ap, bp, draw| {
        let (remote, proof) = begin(a, b, bp, draw)?;
        let mut bad = proof;
        bad[0] ^= 1;
        assert!(matches!(
            a.authentication(remote, &bad, true, draw)?,
            Event::AwaitIdentityDh(_)
        ));
        let generation = a.snapshot().candidate;
        assert!(matches!(
            a.advance_identity_dh(a.scope(), ap, MonoInstant(0))?,
            Event::IdentityDhSubmitted(_)
        ));
        ap.ready = true;
        assert_eq!(
            a.advance_identity_dh(a.scope(), ap, MonoInstant(0)),
            Err(Error::Authentication)
        );
        assert!(a.snapshot().confirmed.is_none());
        assert_eq!(a.snapshot().candidate, generation);
        assert!(a.pending_identity_dh().is_none());
        assert_eq!(ap.submitted, 1);
        assert!(matches!(
            a.authentication(remote, &proof, true, draw)?,
            Event::Confirmed(_)
        ));
        confirm_betty(b, a, draw)?;
        let confirmed = a.snapshot().confirmed;
        let snapshot = a.crypto_snapshot();
        assert_eq!(
            a.authentication(remote, &proof, true, draw)?,
            Event::Duplicate
        );
        assert_eq!(a.snapshot().confirmed, confirmed);
        assert_eq!(a.crypto_snapshot(), snapshot);
        assert_eq!(ap.submitted, 1);
        assert_eq!(ap.finished, 1);
        Ok(())
    })
}
