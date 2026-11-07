# STATISTICS callback ownership contracts

The real public driver uniquely borrows its owner during callback dispatch.
The restricted context can queue/cancel operations; destruction stays outside
that callback. Frame and selector views are borrowed only for the callback.

Keeping owned copies and queuing through the restricted context compiles.
Owner<'owner> destruction remains available outside its callback. The controls below
only type-check; no peer is created and no network operation is executed.

```rust
//! Type-check-only witness using the real public STATISTICS driver.
#![forbid(unsafe_code)]
use gnunet_client::{statistics::Selector, statistics_handle::GetFlow};
use gnunet_ipc_unix::{
    IpcError,
    handle::{Event, StatisticsHandle},
};
type Owner<'owner> = StatisticsHandle<'owner, 4, 32, 2, 4, 4>;
/// Check the callback ownership/lifetime contract without executing I/O.
pub async fn owned_copy_and_restricted_queue<'owner>(owner: &mut Owner<'owner>) -> Result<Vec<Vec<u8>>, IpcError> {
    let mut copies = Vec::new();
    owner
        .drive(None, |event, context| {
            if let Event::GetValue { statistic, .. } = event {
                copies.push(statistic.selector.name.to_vec());
                if context.set(b"copied", statistic.value, false).is_err() {
                    return GetFlow::AbortIteration;
                }
                if context
                    .get(Selector {
                        subsystem: b"s",
                        name: b"next",
                    })
                    .is_err()
                {
                    return GetFlow::AbortIteration;
                }
            }
            GetFlow::Continue
        })
        .await?;
    Ok(copies)
}
/// Owner<'owner> destruction remains available to the caller outside its callback.
pub fn owner_destroy_outside_callback<'owner>(owner: &mut Owner<'owner>) -> Result<(), IpcError> {
    owner.destroy(false)
}
# let _controls = (owned_copy_and_restricted_queue, owner_destroy_outside_callback);
```

The restricted callback context has no destroy operation (E0599).

```compile_fail,E0599
//! Type-check-only witness using the real public STATISTICS driver.
#![forbid(unsafe_code)]
use gnunet_client::statistics_handle::GetFlow;
use gnunet_ipc_unix::{IpcError, handle::StatisticsHandle};
type Owner<'owner> = StatisticsHandle<'owner, 4, 32, 2, 4, 4>;
/// Check the callback ownership/lifetime contract without executing I/O.
pub async fn forbidden<'owner>(owner: &mut Owner<'owner>) -> Result<(), IpcError> {
    owner
        .drive(None, |_, context| {
            if context.destroy(false).is_err() {
                return GetFlow::AbortIteration;
            }
            GetFlow::Continue
        })
        .await?;
    Ok(())
}
# let _witness = forbidden;
```

Capturing the same mutable owner to destroy it during its own drive callback
violates the mutable borrow (E0500/E0501 on the pinned toolchain). The separate
runner checks exact error codes, primary local source spans and diagnostic text.

```compile_fail,E0500,E0501
//! Type-check-only witness using the real public STATISTICS driver.
#![forbid(unsafe_code)]
use gnunet_client::statistics_handle::GetFlow;
use gnunet_ipc_unix::{IpcError, handle::StatisticsHandle};
type Owner<'owner> = StatisticsHandle<'owner, 4, 32, 2, 4, 4>;
/// Check the callback ownership/lifetime contract without executing I/O.
pub async fn forbidden<'owner>(owner: &mut Owner<'owner>) -> Result<(), IpcError> {
    owner
        .drive(None, |_, _| {
            if owner.destroy(false).is_err() {
                return GetFlow::AbortIteration;
            }
            GetFlow::Continue
        })
        .await?;
    Ok(())
}
# let _witness = forbidden;
```

A view borrowed from the received frame cannot escape the callback (E0521).
The owned-copy example above supplies a compiling control with the same types.

```compile_fail,E0521
//! Type-check-only witness using the real public STATISTICS driver.
#![forbid(unsafe_code)]
use gnunet_client::statistics_handle::GetFlow;
use gnunet_ipc_unix::{
    IpcError,
    handle::{Event, StatisticsHandle},
};
type Owner<'owner> = StatisticsHandle<'owner, 4, 32, 2, 4, 4>;
/// Check the callback ownership/lifetime contract without executing I/O.
pub async fn forbidden<'owner>(owner: &mut Owner<'owner>) -> Result<(), IpcError> {
    let mut escaped: Option<&[u8]> = None;
    owner
        .drive(None, |event, _| {
            if let Event::GetValue { statistic, .. } = event {
                escaped = Some(statistic.selector.name);
            }
            GetFlow::Continue
        })
        .await?;
    if let Some(name) = escaped {
        std::hint::black_box(name);
    }
    Ok(())
}
# let _witness = forbidden;
```
