//! Independent bit/order and routing-policy cases, without native IO.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Fallible regressions assert independent protocol bytes and original-owner transitions."
)]
use gnunet_crypto::Entropy;
use gnunet_dht::routing::{self, Candidate, Estimate, PeerBloom};
use gnunet_types::Error;
struct Stream(u64);
impl Entropy for Stream {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), Error> {
        for b in out {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *b = self.0 as u8;
        }
        Ok(())
    }
}
struct Refuse;
impl Entropy for Refuse {
    fn fill(&mut self, _: &mut [u8]) -> Result<(), Error> {
        Err(Error::Io)
    }
}
#[test]
fn official_peer_bloom_is_be_words_and_lsb_bits() {
    let mut key = [0; 64];
    for (i, word) in key.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        word.copy_from_slice(&((i * 67) as u32).to_be_bytes());
    }
    let mut b = PeerBloom::empty();
    b.insert_key(&key);
    let mut expected = [0; 128];
    for bit in [
        0usize, 67, 134, 201, 268, 335, 402, 469, 536, 603, 670, 737, 804, 871, 938, 1005,
    ] {
        expected[bit / 8] |= 1 << (bit % 8);
    }
    assert_eq!(b.as_bytes(), &expected);
    assert!(b.contains_key(&key));
    key[..4].copy_from_slice(&1023u32.to_be_bytes());
    assert!(!b.contains_key(&key));
    assert!(PeerBloom::from_bytes([255; 128]).contains_key(&key));
}
#[test]
fn unsigned_xor_and_msb_bucket_do_not_follow_native_word_order() {
    let zero = [0; 64];
    let mut a = zero;
    let mut b = zero;
    a[0] = 1;
    b[63] = 255;
    assert_eq!(
        routing::distance_cmp(&a, &b, &zero),
        core::cmp::Ordering::Greater
    );
    assert_eq!(routing::bucket(&zero, &a), Some(7));
    assert_eq!(routing::bucket(&zero, &b), Some(504));
    assert_eq!(routing::bucket(&a, &a), None);
}
#[test]
fn replication_probability_and_ttl_boundaries_are_explicit() -> Result<(), Error> {
    let n = Estimate::new(4.0)?;
    assert_eq!(n.fanout(0, 3, 0), 2);
    assert_eq!(n.fanout(0, 3, u32::MAX), 1);
    assert_eq!(n.fanout(8, 16, u32::MAX), 1);
    assert_eq!(n.fanout(9, 16, 0), 1);
    assert_eq!(n.fanout(16, 16, 0), 1);
    assert_eq!(n.fanout(17, 16, 0), 0);
    assert_eq!(n.fanout(0, 0, 0), 1);
    assert_eq!(Estimate::new(-1.0)?.log2(), 0.5);
    assert_eq!(Estimate::new(0.0)?.fanout(0, 65535, 0), 16);
    assert!(Estimate::new(f64::NAN).is_err());
    assert!(Estimate::new(f64::INFINITY).is_err());
    Ok(())
}
#[test]
fn greedy_selection_is_distinct_filtered_and_original_session_bound() -> Result<(), Error> {
    let peers: Vec<_> = (1..=30)
        .map(|i| Candidate {
            origin: i,
            identity: [i; 32],
        })
        .collect();
    let target = routing::peer_key(&peers[7].identity);
    let mut visited = PeerBloom::empty();
    visited.insert_key(&target);
    let p = routing::plan(
        &[0; 32],
        &target,
        &peers,
        visited,
        Estimate::new(2.0)?,
        2,
        16,
        8,
        &mut Stream(7),
    )?;
    let selected: Vec<_> = p.selected().collect();
    assert!(!selected.contains(&8));
    let mut sorted = selected.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(selected.len(), sorted.len());
    let mut expected: Vec<_> = peers.iter().filter(|p| p.origin != 8).collect();
    // A larger bucket cap includes every candidate, allowing an independent full sort.
    expected.sort_by(|a, b| {
        routing::distance_cmp(
            &routing::peer_key(&a.identity),
            &routing::peer_key(&b.identity),
            &target,
        )
    });
    let p = routing::plan(
        &[0; 32],
        &target,
        &peers,
        visited,
        Estimate::new(2.0)?,
        2,
        16,
        64,
        &mut Stream(7),
    )?;
    assert_eq!(p.selected().next(), Some(expected[0].origin));
    assert!(!routing::am_closest(&[0; 32], &target, &peers, None, 64));
    assert!(routing::am_closest(
        &[0; 32],
        &target,
        &peers,
        Some(&PeerBloom::from_bytes([255; 128])),
        64
    ));
    Ok(())
}
#[test]
fn first_bucket_membership_limit_and_random_selection_keep_bloom_semantics() -> Result<(), Error> {
    let peers: Vec<_> = (1..=40)
        .map(|i| Candidate {
            origin: i,
            identity: [i; 32],
        })
        .collect();
    let local = routing::peer_key(&[0; 32]);
    let (first, later) = peers
        .iter()
        .enumerate()
        .find_map(|(i, first)| {
            let index = routing::bucket(&local, &routing::peer_key(&first.identity));
            peers[i + 1..]
                .iter()
                .find(|p| routing::bucket(&local, &routing::peer_key(&p.identity)) == index)
                .map(|later| (first, later))
        })
        .ok_or(Error::InvalidInput)?;
    let candidates = [*first, *later];
    let target = routing::peer_key(&later.identity);
    let p = routing::plan(
        &[0; 32],
        &target,
        &candidates,
        PeerBloom::empty(),
        Estimate::new(0.5)?,
        1,
        16,
        1,
        &mut Stream(7),
    )?;
    assert_eq!(p.selected().collect::<Vec<_>>(), vec![first.origin]);
    let p = routing::plan(
        &[0; 32],
        &target,
        &peers,
        PeerBloom::empty(),
        Estimate::new(4.0)?,
        0,
        16,
        8,
        &mut Stream(19),
    )?;
    for id in p.selected() {
        assert!(p.bloom().contains_key(&routing::peer_key(&[id; 32])));
    }
    Ok(())
}
#[test]
fn entropy_failure_and_ttl_never_mutate_original_filter() -> Result<(), Error> {
    let peers = [
        Candidate {
            origin: 1,
            identity: [1; 32],
        },
        Candidate {
            origin: 2,
            identity: [2; 32],
        },
    ];
    let b = PeerBloom::empty();
    assert!(matches!(
        routing::plan(
            &[0; 32],
            &[0; 64],
            &peers,
            b,
            Estimate::new(4.0)?,
            0,
            16,
            8,
            &mut Refuse
        ),
        Err(Error::Entropy)
    ));
    assert_eq!(b, PeerBloom::empty());
    let p = routing::plan(
        &[0; 32],
        &[0; 64],
        &peers,
        b,
        Estimate::new(1.0)?,
        5,
        16,
        8,
        &mut Refuse,
    )?;
    assert_eq!(p.selected().count(), 0);
    Ok(())
}
