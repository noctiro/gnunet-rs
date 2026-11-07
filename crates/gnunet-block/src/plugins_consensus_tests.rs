//! Source-only installed callback and no-group cases, with caller-owned inert ports.
use super::*;
fn check(v: bool) -> Result<(), Error> {
    if v { Ok(()) } else { Err(Error::Conflict) }
}
#[test]
fn installed_old_set_and_consensus_callbacks_keep_actual_no_group_contract() -> Result<(), Error> {
    let selected = [Plugin::SetTest, Plugin::Consensus];
    let ctx = Context::new(&selected, NativeEndian::native());
    let (mut hello, mut pow) = ([], []);
    let mut work = Work {
        hello: &mut hello,
        hello_limits: gnunet_hello::Limits {
            maximum_input_bytes: 0,
            maximum_address_bytes: 0,
            maximum_addresses: 0,
        },
        hello_profile: gnunet_hello::SignatureProfile::Gnunet029,
        pow: &mut pow,
    };
    let mut clock = || 0;
    check(ctx.check_query(BlockType::SET_TEST, &[0; 64], &[1, 2]) == ReturnValue::Yes)?;
    check(ctx.check_query(BlockType::CONSENSUS_ELEMENT, &[0; 64], &[]) == ReturnValue::SysErr)?;
    check(
        ctx.check_block(BlockType::SET_TEST, &[0, 1], &mut work, &mut clock)? == ReturnValue::Yes,
    )?;
    check(
        ctx.check_block(BlockType::SET_TEST, &[], &mut work, &mut clock)? == ReturnValue::SysErr,
    )?;
    check(
        ctx.get_key(BlockType::SET_TEST, &[0], &mut work, &mut clock)?
            .status
            == ReturnValue::No,
    )?;
    check(
        ctx.get_key(
            BlockType::CONSENSUS_ELEMENT,
            &[0, 0, 1],
            &mut work,
            &mut clock,
        )?
        .status
            == ReturnValue::SysErr,
    )?;
    // BE16 nested24 is dispatched as24 on every host, not C's little-endian24<<16.
    check(
        ctx.check_block(
            BlockType::CONSENSUS_ELEMENT,
            &[0, 24, 0, 0],
            &mut work,
            &mut clock,
        )? == ReturnValue::Yes,
    )?;
    check(
        ctx.check_block(
            BlockType::CONSENSUS_ELEMENT,
            &[0, 24, 0, 1],
            &mut work,
            &mut clock,
        )? == ReturnValue::SysErr,
    )?;
    check(
        ctx.check_block(BlockType::CONSENSUS_ELEMENT, &[0, 0], &mut work, &mut clock)?
            == ReturnValue::No,
    )?;
    check(
        ctx.check_reply(
            BlockType::CONSENSUS_ELEMENT,
            None,
            &[0; 64],
            None,
            &[0, 0, 1],
            &mut work,
            &mut clock,
        )? == ReplyEvaluation::More,
    )?;
    let mut storage = [9; 8];
    check(
        ctx.create_group(
            BlockType::CONSENSUS_ELEMENT,
            GroupSizing::FilterBytes(8),
            None,
            3,
            &mut storage,
        )?
        .is_none(),
    )?;
    check(storage == [9; 8])?;
    let mut deep = [0; 3 * (MAX_CONSENSUS_NESTING + 1) + 1];
    for chunk in deep[..3 * (MAX_CONSENSUS_NESTING + 1)]
        .as_chunks_mut::<3>()
        .0
    {
        *chunk = [0, 25, 0];
    }
    check(
        ctx.check_block(BlockType::CONSENSUS_ELEMENT, &deep, &mut work, &mut clock)
            == Err(Error::Capacity),
    )?;
    // Both production registry forms resolve the nested type through their
    // selected full registry, preserving the original query/group and bytes.
    let callbacks = crate::callbacks::CallbackContext::new(selected, NativeEndian::native());
    check(
        callbacks.check_block(
            BlockType::CONSENSUS_ELEMENT,
            &[0, 24, 0, 0],
            &mut work,
            &mut clock,
        )? == ReturnValue::Yes,
    )?;
    check(
        callbacks.check_reply(
            BlockType::CONSENSUS_ELEMENT,
            None,
            crate::callbacks::Reply {
                query: &[0; 64],
                xquery: None,
                block: &[0, 24, 0, 0],
            },
            &mut work,
            &mut clock,
        )? == ReplyEvaluation::More,
    )?;
    check(
        callbacks.check_block(BlockType::CONSENSUS_ELEMENT, &deep, &mut work, &mut clock)
            == Err(Error::Capacity),
    )?;
    let missing =
        crate::callbacks::CallbackContext::new([Plugin::Consensus], NativeEndian::native());
    check(
        missing.check_block(
            BlockType::CONSENSUS_ELEMENT,
            &[0, 24, 0, 0],
            &mut work,
            &mut clock,
        )? == ReturnValue::SysErr,
    )
}
