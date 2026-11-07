//! Exercise the actual safe public plugin callback interface and owned lifetime.
use gnunet_block::{
    BlockType, GroupState, Hash, ReplyEvaluation, ReturnValue,
    bloom::{BloomGroup, NativeEndian},
    callbacks::{CallbackContext, PluginFunctions, Reply},
    plugins::{Clock, Context, GroupSizing, KeyResult, Plugin, Work},
    pow,
};
use gnunet_crypto::hash512;
use gnunet_types::Error;
use std::cell::Cell;
struct Extension<'a> {
    id: u8,
    calls: &'a Cell<u32>,
    drops: &'a Cell<u32>,
}
impl Drop for Extension<'_> {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() * 10 + u32::from(self.id));
    }
}
impl PluginFunctions for Extension<'_> {
    type Creation<'a>
        = u32
    where
        Self: 'a;
    type Group<'a>
        = BloomGroup<'a>
    where
        Self: 'a;
    fn types(&self) -> &[BlockType] {
        &[BlockType(101), BlockType::ANY, BlockType(102)]
    }
    fn create_group<'a>(
        &'a self,
        kind: BlockType,
        size: u32,
        raw: Option<&'a [u8]>,
        nonce: u32,
        storage: &'a mut [u8],
        profile: NativeEndian,
    ) -> Result<Option<BloomGroup<'a>>, Error> {
        self.calls.set(self.calls.get() + 1);
        if storage.len() < size as usize {
            return Err(Error::Capacity);
        }
        BloomGroup::new(&mut storage[..size as usize], kind, 16, raw, nonce, profile).map(Some)
    }
    fn get_key(
        &self,
        _: BlockType,
        b: &[u8],
        _: &mut Work<'_>,
        _: &mut dyn Clock,
    ) -> Result<KeyResult, Error> {
        self.calls.set(self.calls.get() + 1);
        Ok(KeyResult {
            status: ReturnValue::Yes,
            key: Some(hash512(b)),
        })
    }
    fn check_query(&self, _: BlockType, q: &Hash, x: Option<&[u8]>) -> ReturnValue {
        self.calls.set(self.calls.get() + 1);
        if x.is_none() {
            return ReturnValue::SysErr;
        }
        if q[0] == self.id && x == Some(b"exact\0".as_slice()) {
            ReturnValue::Yes
        } else {
            ReturnValue::No
        }
    }
    fn check_block(
        &self,
        _: BlockType,
        b: &[u8],
        _: &mut Work<'_>,
        clock: &mut dyn Clock,
    ) -> Result<ReturnValue, Error> {
        self.calls.set(self.calls.get() + 1);
        Ok(if b == [self.id] && clock.now() == 123 {
            ReturnValue::Yes
        } else {
            ReturnValue::No
        })
    }
    fn check_reply<'a>(
        &self,
        _: BlockType,
        group: Option<&mut BloomGroup<'a>>,
        request: Reply<'_>,
        _: &mut Work<'_>,
        _: &mut dyn Clock,
    ) -> Result<ReplyEvaluation, Error>
    where
        Self: 'a,
    {
        self.calls.set(self.calls.get() + 1);
        if request.xquery != Some(b"exact\0".as_slice()) || request.query[0] != self.id {
            return Ok(ReplyEvaluation::Irrelevant);
        }
        Ok(
            if gnunet_block::bloom::test_and_set(group, &hash512(request.block)) {
                ReplyEvaluation::Duplicate
            } else {
                ReplyEvaluation::More
            },
        )
    }
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions accompany fallible fixture construction"
)]
fn custom_plugin_callbacks_preserve_inputs_first_match_and_owning_drop() -> Result<(), Error> {
    let calls = Cell::new(0);
    let other = Cell::new(0);
    let drops = Cell::new(0);
    let ctx = CallbackContext::new(
        [
            Extension {
                id: 3,
                calls: &calls,
                drops: &drops,
            },
            Extension {
                id: 4,
                calls: &other,
                drops: &drops,
            },
        ],
        NativeEndian::native(),
    );
    let kind = BlockType(101);
    let mut q = [0; 64];
    q[0] = 3;
    assert_eq!(
        ctx.check_query(kind, &q, Some(b"exact\0")),
        ReturnValue::Yes
    );
    assert_eq!(
        ctx.check_query(BlockType::ANY, &q, Some(b"exact\0")),
        ReturnValue::SysErr
    );
    assert_eq!(
        ctx.check_query(BlockType(102), &q, Some(b"exact\0")),
        ReturnValue::SysErr
    );
    assert_eq!(ctx.check_query(kind, &q, None), ReturnValue::SysErr);
    assert_eq!(ctx.check_query(kind, &q, Some(&[])), ReturnValue::No);
    assert_eq!(other.get(), 0);
    let mut hello = [];
    let mut memory = [];
    let mut work = Work {
        hello: &mut hello,
        hello_limits: gnunet_hello::Limits {
            maximum_input_bytes: 0,
            maximum_address_bytes: 0,
            maximum_addresses: 0,
        },
        hello_profile: gnunet_hello::SignatureProfile::Gnunet029,
        pow: &mut memory,
    };
    let mut now = || 123;
    assert_eq!(
        ctx.get_key(kind, b"payload", &mut work, &mut now)?.key,
        Some(hash512(b"payload"))
    );
    assert_eq!(
        ctx.check_block(kind, &[3], &mut work, &mut now)?,
        ReturnValue::Yes
    );
    let mut bytes = [0xa5; 8];
    let mut group = ctx
        .create_group(kind, 8, Some(&[0; 4]), 0, &mut bytes)?
        .ok_or(Error::NotReady)?;
    assert_eq!(group.block_type(), kind);
    let request = Reply {
        query: &q,
        xquery: Some(b"exact\0"),
        block: b"reply",
    };
    assert_eq!(
        ctx.check_reply(kind, Some(&mut group), request, &mut work, &mut now)?,
        ReplyEvaluation::More
    );
    assert_eq!(
        ctx.check_reply(kind, Some(&mut group), request, &mut work, &mut now)?,
        ReplyEvaluation::Duplicate
    );
    assert_eq!(calls.get(), 8);
    drop(ctx);
    assert_eq!(drops.get(), 34);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Test assertions accompany fallible fixture construction"
)]
fn owning_builtin_registry_routes_all_installed_types_without_allocator_state() -> Result<(), Error>
{
    let plugins = [
        Plugin::Test,
        Plugin::Dht,
        Plugin::Fs,
        Plugin::Gns,
        Plugin::Dns,
        Plugin::Regex,
        Plugin::Revocation(gnunet_block::plugins::RevocationConfig {
            matching_bits: 0,
            epoch_duration: 1,
        }),
        Plugin::SetIntersection,
        Plugin::SetUnion,
    ];
    let borrowed = Context::new(&plugins, NativeEndian::native());
    let owned = CallbackContext::new(plugins, NativeEndian::native());
    let query = [0; 64];
    for kind in [
        0, 1, 2, 6, 7, 8, 9, 10, 11, 12, 13, 22, 23, 24, 25, 26, 27, 99,
    ] {
        for x in [b"".as_slice(), b"x", b"x\0"] {
            assert_eq!(
                owned.check_query(BlockType(kind), &query, Some(x)),
                borrowed.check_query(BlockType(kind), &query, x)
            );
        }
    }
    let mut storage = [0; 16];
    let group = owned
        .create_group(
            BlockType::TEST,
            GroupSizing::SeenSet(1),
            Some(&[0; 4]),
            0,
            &mut storage,
        )?
        .ok_or(Error::NotReady)?;
    assert_eq!(group.bits().len(), 8);
    let _: Option<&pow::Block> = None;
    Ok(())
}
