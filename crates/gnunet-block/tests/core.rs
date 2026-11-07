//! Source-defined nullable groups, native bytes, wrapping size and caller capacity.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Exact source semantics and output atomicity assertions"
)]
use gnunet_block::{
    BlockType, GroupState, Hash, MergeOutcome, ReturnValue,
    bloom::{BloomGroup, NativeEndian, compute_size, mingle_hash, test_and_set},
    group_merge, group_serialize, group_set_seen, pow,
};
use gnunet_types::Error;
#[test]
fn unsigned32_size_wrap_early_entry_cap_and_exact_native_mingle() {
    assert_eq!(compute_size(0, u32::MAX), 8);
    assert_eq!(compute_size(32768, 0x8000_0000), 8);
    assert_eq!(compute_size(32769, 0), 32768);
    assert_eq!(compute_size(10, 16), 64);
    let hash = [0x5a; 64];
    let mut bytes = [0x5a; 68];
    bytes[64..].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    assert_eq!(
        mingle_hash(&hash, 0x1234_5678, NativeEndian::Little),
        gnunet_crypto::hash512(&bytes)
    );
    bytes[64..].copy_from_slice(&0x1234_5678u32.to_be_bytes());
    assert_eq!(
        mingle_hash(&hash, 0x1234_5678, NativeEndian::Big),
        gnunet_crypto::hash512(&bytes)
    );
}
#[test]
fn raw_prefix_length_nonce_and_serialize_failures_preserve_real_semantics() -> Result<(), Error> {
    let mut bytes = [0xa5; 8];
    assert!(matches!(
        BloomGroup::new(
            &mut bytes,
            BlockType::TEST,
            16,
            Some(&[0, 1, 2]),
            7,
            NativeEndian::Little
        ),
        Err(Error::Truncated)
    ));
    assert_eq!(bytes, [0xa5; 8]);
    let raw = [0x78, 0x56, 0x34, 0x12, 0xff];
    let mut group = BloomGroup::new(
        &mut bytes,
        BlockType::TEST,
        16,
        Some(&raw),
        7,
        NativeEndian::Little,
    )?;
    assert_eq!(group.nonce(), 0x1234_5678);
    assert_eq!(group.bits(), [0; 8]);
    let hash = gnunet_crypto::hash512(b"seen");
    assert!(!group.test_and_set(&hash));
    assert!(group.test_and_set(&hash));
    let mut too_short = [0xa5; 11];
    assert_eq!(group.serialize_into(&mut too_short), Err(Error::Capacity));
    assert_eq!(too_short, [0xa5; 11]);
    let mut serialized = [0; 12];
    assert_eq!(group.serialize_into(&mut serialized)?, Some(12));
    assert_eq!(&serialized[..4], &raw[..4]);
    let mut restored = [0; 8];
    let mut restored = BloomGroup::new(
        &mut restored,
        BlockType::DNS,
        16,
        Some(&serialized),
        1,
        NativeEndian::Little,
    )?;
    assert!(restored.test_and_set(&hash));
    Ok(())
}
#[test]
fn null_group_is_not_duplicate_but_null_internal_filter_is_duplicate() -> Result<(), Error> {
    assert!(!test_and_set(None, &[0; 64]));
    let mut output = [0xa5; 12];
    assert_eq!(group_serialize::<BloomGroup<'_>>(None, &mut output)?, None);
    assert_eq!(
        group_set_seen::<BloomGroup<'_>>(None, &[[0; 64]]),
        ReturnValue::Yes
    );
    assert_eq!(output, [0xa5; 12]);
    for k in [0, 0x8000_0000, u32::MAX] {
        let mut storage = [0; 8];
        let mut group = BloomGroup::new(
            &mut storage,
            BlockType::TEST,
            k,
            None,
            1,
            NativeEndian::native(),
        )?;
        assert!(group.test_and_set(&[0; 64]));
        if k == 0 {
            assert_eq!(group.serialize_into(&mut output), Err(Error::NotReady));
        } else {
            assert_eq!(group.serialize_into(&mut output)?, Some(12));
        }
    }
    let mut storage = [];
    let mut empty = BloomGroup::new(
        &mut storage,
        BlockType::TEST,
        16,
        None,
        9,
        NativeEndian::native(),
    )?;
    assert!(empty.test_and_set(&[0; 64]));
    Ok(())
}
#[test]
fn rehash_rounds_and_merge_only_require_nonce_size_not_k_or_type() -> Result<(), Error> {
    let mut a = [0; 9];
    let mut b = [0; 9];
    let mut left = BloomGroup::new(
        &mut a,
        BlockType::FS_UBLOCK,
        17,
        None,
        5,
        NativeEndian::native(),
    )?;
    let mut right = BloomGroup::new(
        &mut b,
        BlockType::DHT_HELLO,
        33,
        None,
        5,
        NativeEndian::native(),
    )?;
    let hash = gnunet_crypto::hash512(b"right");
    assert!(!right.test_and_set(&hash));
    assert!(matches!(
        group_merge(Some(&mut left), Some(right))?,
        MergeOutcome::Consumed(ReturnValue::Yes)
    ));
    assert!(left.test_and_set(&hash));
    let mut mismatch = [0; 9];
    let mismatch = BloomGroup::new(
        &mut mismatch,
        BlockType::TEST,
        16,
        None,
        6,
        NativeEndian::native(),
    )?;
    assert!(matches!(
        group_merge(Some(&mut left), Some(mismatch))?,
        MergeOutcome::Consumed(ReturnValue::No)
    ));
    Ok(())
}
#[test]
fn absent_merge_callback_retains_second_owner_but_null_left_consumes_it() -> Result<(), Error> {
    use std::cell::Cell;
    struct Custom<'a> {
        drops: &'a Cell<u32>,
    }
    impl Drop for Custom<'_> {
        fn drop(&mut self) {
            self.drops.set(self.drops.get() + 1);
        }
    }
    impl GroupState for Custom<'_> {
        fn block_type(&self) -> BlockType {
            BlockType::TEST
        }
        fn serialize_into(&self, _: &mut [u8]) -> Result<Option<usize>, Error> {
            Ok(None)
        }
        fn mark_seen(&mut self, _: &[Hash]) -> gnunet_block::MarkSeen {
            gnunet_block::MarkSeen::Unsupported
        }
        fn has_merge(&self) -> bool {
            false
        }
        fn merge_from(&mut self, _: &Self) -> Result<ReturnValue, Error> {
            Err(Error::Unsupported)
        }
    }
    let drops = Cell::new(0);
    let mut left = Custom { drops: &drops };
    let right = Custom { drops: &drops };
    let result = group_merge(Some(&mut left), Some(right))?;
    assert_eq!(drops.get(), 0);
    let MergeOutcome::Unsupported(retained) = result else {
        return Err(Error::Malformed);
    };
    assert_eq!(drops.get(), 0);
    assert!(matches!(
        group_merge(None, Some(retained))?,
        MergeOutcome::Consumed(ReturnValue::Yes)
    ));
    assert_eq!(drops.get(), 1);
    drop(left);
    assert_eq!(drops.get(), 2);
    Ok(())
}
#[test]
fn pow_uses_caller_memory_and_short_scratch_cannot_change_output() -> Result<(), Error> {
    let mut short = vec![pow::Block::new(); pow::MEMORY_BLOCKS - 1];
    let mut output = [0xa5; 64];
    assert_eq!(
        pow::hash(&[0; 16], b"", &mut output, &mut short),
        Err(Error::Capacity)
    );
    assert_eq!(output, [0xa5; 64]);
    let mut full = vec![pow::Block::new(); pow::MEMORY_BLOCKS];
    pow::hash(&[0; 16], b"", &mut output, &mut full)?;
    assert_ne!(output, [0xa5; 64]);
    let first = output;
    pow::hash(&[0; 16], b"x", &mut output, &mut full)?;
    assert_ne!(output, first);
    pow::hash(&[0; 16], b"", &mut output, &mut full)?;
    assert_eq!(output, first);
    Ok(())
}
#[test]
fn builtin_restore_copies_raw_state_before_its_owner_is_released() -> Result<(), Error> {
    use gnunet_block::plugins::{Context, GroupSizing, Plugin};
    let mut storage = [0; 8];
    let plugins = [Plugin::Test];
    let context = Context::new(&plugins, NativeEndian::Little);
    let group = {
        let raw = vec![4, 3, 2, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        context
            .create_group(
                BlockType::TEST,
                GroupSizing::FilterBytes(8),
                Some(&raw),
                0,
                &mut storage,
            )?
            .ok_or(Error::NotReady)?
    };
    let mut output = [0; 12];
    assert_eq!(group.serialize_into(&mut output)?, Some(12));
    assert_eq!(
        output,
        [4, 3, 2, 1, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    );
    Ok(())
}
