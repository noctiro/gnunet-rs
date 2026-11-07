use super::*;

struct RejectThenUnit {
    calls: usize,
}
impl Entropy for RejectThenUnit {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), gnunet_types::Error> {
        // Zero, a nonunit and an out-of-range value must not become witnesses.
        let value = match self.calls {
            0 => 0,
            1 => 3,
            2 => 15,
            _ => 2,
        };
        self.calls += 1;
        bytes.fill(0);
        *bytes.last_mut().ok_or(gnunet_types::Error::InvalidInput)? = value;
        Ok(())
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "The exact shared production encryption jobs are compared against independent small public Paillier algebra"
)]
fn witness_is_the_actual_unit_and_ordinary_encryption_keeps_identical_progress_and_bytes()
-> Result<(), Error> {
    let pair = tiny_pair()?;
    let limits = Limits {
        units_per_turn: 64,
        ..Limits::default()
    };
    let mut ordinary = pair
        .public
        .encrypt(pair.public.plaintext(&[7])?, 0, limits)?;
    let mut witnessed =
        pair.public
            .encrypt_with_witness(pair.public.plaintext(&[7])?, 0, limits)?;
    assert!(matches!(witnessed.take_result(), Err(Error::NotReady)));
    let mut left = RejectThenUnit { calls: 0 };
    let mut right = RejectThenUnit { calls: 0 };
    for _ in 0..34 {
        let progress = ordinary.advance(&mut left, 64)?;
        assert_eq!(witnessed.advance(&mut right, 64)?, progress);
        assert_eq!(left.calls, right.calls);
        if progress == Progress::Ready {
            break;
        }
    }
    assert_eq!(left.calls, 4);
    let ordinary = ordinary.take_result()?;
    let result = witnessed.take_result()?;
    assert_eq!(result.modulus(), &pair.public.to_bytes());
    assert_eq!(result.ciphertext().to_wire(), ordinary.to_wire());
    assert!(matches!(witnessed.take_result(), Err(Error::Finished)));
    let (ciphertext, randomizer) = result.into_parts();
    assert!(randomizer[..255].iter().all(|byte| *byte == 0));
    assert_eq!(randomizer[255], 2);
    let unit = u128::from(randomizer[255]);
    assert_eq!(
        U2048::from_be_slice(randomizer.as_ref()).gcd(&pair.public.n),
        U2048::ONE,
    );
    // Independent public-integer relation: E_15(7;2)=(1+15*7)*2^15 mod225=83.
    let expected = ((1 + 15 * 7) * unit.pow(15)) % 225;
    assert_eq!(expected, 83);
    assert_eq!(ciphertext.integer(), U4096::from(expected));
    assert_eq!(ciphertext.remaining_ops(), 0);
    Ok(())
}

struct ZeroNonce;
impl Entropy for ZeroNonce {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), gnunet_types::Error> {
        bytes.fill(0);
        Ok(())
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Actual failed, cancelled and exhausted witness jobs must never expose secret witness output"
)]
fn witness_entropy_failure_partial_and_ready_cancellation_and_rejection_budget_are_terminal()
-> Result<(), Error> {
    let pair = tiny_pair()?;
    let limits = Limits {
        units_per_turn: 64,
        ..Limits::default()
    };
    let make = || {
        pair.public
            .encrypt_with_witness(pair.public.plaintext(&[7])?, 0, limits)
    };
    let original = Error::Entropy(gnunet_types::Error::Unavailable);
    let mut failed = make()?;
    assert_eq!(failed.advance(&mut PartialFailure, 1), Err(original));
    failed.cancel();
    assert_eq!(failed.advance(&mut AlgebraNonce, 1), Err(original));
    assert!(matches!(failed.take_result(), Err(error) if error == original));

    let mut partial = make()?;
    assert_eq!(partial.advance(&mut AlgebraNonce, 1)?, Progress::Advanced);
    partial.cancel();
    assert_eq!(partial.advance(&mut AlgebraNonce, 1), Err(Error::Cancelled));
    assert!(matches!(partial.take_result(), Err(Error::Cancelled)));

    let mut ready = make()?;
    for _ in 0..34 {
        if ready.advance(&mut AlgebraNonce, 64)? == Progress::Ready {
            break;
        }
    }
    assert_eq!(ready.advance(&mut AlgebraNonce, 64)?, Progress::Ready);
    ready.cancel();
    assert!(matches!(ready.take_result(), Err(Error::Cancelled)));

    let mut exhausted = pair.public.encrypt_with_witness(
        pair.public.plaintext(&[7])?,
        0,
        Limits {
            rejections: 1,
            ..limits
        },
    )?;
    assert_eq!(exhausted.advance(&mut ZeroNonce, 1)?, Progress::Advanced);
    assert_eq!(exhausted.advance(&mut ZeroNonce, 1), Err(Error::Capacity));
    assert!(matches!(exhausted.take_result(), Err(Error::Capacity)));
    Ok(())
}
