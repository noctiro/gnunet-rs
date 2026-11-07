//! Explicit validation/reply and resource boundaries, without implicit time.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions accompany fallible signed fixtures"
)]
use gnunet_block::{
    BlockType, ReplyEvaluation, ReturnValue,
    bloom::NativeEndian,
    plugins::{Context, Plugin, Work},
};
use gnunet_crypto::EddsaPrivateKey;
use gnunet_types::Error;
fn work<'a>(hello: &'a mut [u8]) -> Work<'a> {
    Work {
        hello,
        hello_limits: gnunet_hello::Limits {
            maximum_input_bytes: 65535,
            maximum_address_bytes: 65535,
            maximum_addresses: 1024,
        },
        hello_profile: gnunet_hello::SignatureProfile::Gnunet029,
        pow: &mut [],
    }
}
fn dns(expiration: u64) -> Result<[u8; 112], Error> {
    let key = EddsaPrivateKey::from_seed([9; 32]);
    let mut b = [0; 112];
    b[64..68].copy_from_slice(&48u32.to_be_bytes());
    b[68..72].copy_from_slice(&11u32.to_be_bytes());
    b[72..80].copy_from_slice(&expiration.to_be_bytes());
    b[80..112].copy_from_slice(key.public_key().as_bytes());
    let sig = key.sign(11, &b[64..])?;
    b[..64].copy_from_slice(sig.as_bytes());
    Ok(b)
}
#[test]
fn dns_exact_expiration_readpoint_and_reply_does_not_revalidate() -> Result<(), Error> {
    let ctx = Context::new(&[Plugin::Dns], NativeEndian::native());
    let mut bytes = [];
    let mut work = work(&mut bytes);
    let block = dns(100)?;
    for now in [99, 100, 101] {
        let mut calls = 0;
        let mut clock = || {
            calls += 1;
            now
        };
        assert_eq!(
            ctx.check_block(BlockType::DNS, &block, &mut work, &mut clock)?,
            if now <= 100 {
                ReturnValue::Yes
            } else {
                ReturnValue::No
            }
        );
        assert_eq!(calls, 1);
    }
    let mut wrong = block;
    wrong[64..68].fill(0);
    let mut calls = 0;
    let mut clock = || {
        calls += 1;
        u64::MAX
    };
    assert_eq!(
        ctx.check_block(BlockType::DNS, &wrong, &mut work, &mut clock)?,
        ReturnValue::No
    );
    assert_eq!(
        ctx.check_reply(
            BlockType::DNS,
            None,
            &[0; 64],
            None,
            &wrong,
            &mut work,
            &mut clock
        )?,
        ReplyEvaluation::More
    );
    assert_eq!(calls, 0);
    Ok(())
}
#[test]
fn hello_capacity_is_resource_failure_and_cannot_be_invalid_or_fallback() -> Result<(), Error> {
    let key = EddsaPrivateKey::from_seed([9; 32]);
    let limits = gnunet_hello::Limits {
        maximum_input_bytes: 65535,
        maximum_address_bytes: 65535,
        maximum_addresses: 1024,
    };
    let mut address = [0; 64];
    let mut builder = gnunet_hello::HelloBuilder::new(&mut address, limits);
    builder.add_address(b"tcp://127.0.0.1:1234")?;
    let hello = builder.sign(
        &key,
        gnunet_hello::AbsoluteTime::from_micros(u64::MAX),
        gnunet_hello::SignatureProfile::Gnunet029,
    )?;
    let mut block = vec![0; hello.block_len()?];
    hello.encode_block(&mut block)?;
    let ctx = Context::new(&[Plugin::Dht], NativeEndian::native());
    let mut storage = [0xa5; 1];
    let mut scratch = work(&mut storage);
    let mut calls = 0;
    let mut clock = || {
        calls += 1;
        0
    };
    assert_eq!(
        ctx.check_block(BlockType::DHT_HELLO, &block, &mut scratch, &mut clock),
        Err(Error::Capacity)
    );
    assert_eq!(
        ctx.get_key(BlockType::DHT_HELLO, &block, &mut scratch, &mut clock),
        Err(Error::Capacity)
    );
    assert_eq!(calls, 0);
    Ok(())
}
#[test]
fn gns_native_assertion_size_is_safe_error_and_unknown_type_key_is_unchanged() -> Result<(), Error>
{
    let ctx = Context::new(&[Plugin::Gns], NativeEndian::native());
    let mut storage = [];
    let mut scratch = work(&mut storage);
    let mut now = || 0;
    let mut block = vec![0; 112 + 65536];
    let n = block.len() as u32;
    block[..4].copy_from_slice(&n.to_be_bytes());
    block[4..8].copy_from_slice(&65556u32.to_be_bytes());
    assert_eq!(
        ctx.check_block(BlockType::GNS_NAMERECORD, &block, &mut scratch, &mut now),
        Err(Error::TooLarge)
    );
    block.truncate(112);
    block[..4].copy_from_slice(&112u32.to_be_bytes());
    block[4..8].copy_from_slice(&99u32.to_be_bytes());
    let key = ctx.get_key(BlockType::GNS_NAMERECORD, &block, &mut scratch, &mut now)?;
    assert_eq!(key.status, ReturnValue::Yes);
    assert_eq!(key.key, None);
    Ok(())
}
#[test]
fn source_assertion_or_pointer_preconditions_are_safe_errors_without_partial_group_update()
-> Result<(), Error> {
    let ctx = Context::new(
        &[Plugin::Regex, Plugin::SetIntersection],
        NativeEndian::native(),
    );
    let mut storage = [];
    let mut scratch = work(&mut storage);
    let mut now = || 0;
    assert_eq!(
        ctx.check_reply(
            BlockType::REGEX_ACCEPT,
            None,
            &[0; 64],
            None,
            &[],
            &mut scratch,
            &mut now
        ),
        Err(Error::Malformed)
    );
    assert_eq!(
        ctx.check_reply(
            BlockType::SETI_TEST,
            None,
            &[0; 64],
            None,
            b"bad",
            &mut scratch,
            &mut now
        ),
        Err(Error::Malformed)
    );
    let block = [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
    let state = gnunet_block::regex::State::parse_prefix(&block)?;
    assert_eq!(state.check(None, None), Err(Error::Malformed));
    Ok(())
}

#[test]
fn maximum_size_headers_are_rejected_without_portable_length_overflow() -> Result<(), Error> {
    use gnunet_block::plugins::RevocationConfig;
    let plugins = [
        Plugin::Fs,
        Plugin::Revocation(RevocationConfig::from_native_values(0, 1)),
    ];
    let context = Context::new(&plugins, NativeEndian::native());
    let mut scratch = [];
    let mut work = work(&mut scratch);
    let mut reads = 0;
    let mut clock = || {
        reads += 1;
        0
    };
    for value in [u32::MAX, u32::MAX - 1, u32::MAX - 63] {
        let mut block = [0; 104];
        block[64..68].copy_from_slice(&value.to_be_bytes());
        assert_eq!(
            context.check_block(BlockType::FS_UBLOCK, &block, &mut work, &mut clock)?,
            ReturnValue::No
        );
    }
    for value in [u32::MAX, u32::MAX - 1, u32::MAX - 7] {
        let mut block = [0; 380];
        block[4..8].copy_from_slice(&value.to_be_bytes());
        block[280..284].copy_from_slice(&65556u32.to_be_bytes());
        assert_eq!(
            context.check_block(BlockType::REVOCATION, &block, &mut work, &mut clock)?,
            ReturnValue::No
        );
        assert_eq!(
            context
                .get_key(BlockType::REVOCATION, &block, &mut work, &mut clock)?
                .key,
            None
        );
    }
    assert_eq!(reads, 0);
    Ok(())
}
