//! Closed-driver authority without starting or polling any socket connection.
#![expect(
    clippy::panic_in_result_fn,
    reason = "The closed-owner witness asserts callback eligibility/order and terminal authority."
)]
use gnunet_client::{statistics::Selector, statistics_handle::GetFlow};
use gnunet_ipc_unix::{
    IpcError,
    handle::{Event, Limits, Progress, StatisticsHandle as Driver},
};
use gnunet_types::Error;
fn selector(name: &[u8]) -> Selector<'_> {
    Selector {
        subsystem: b"s",
        name,
    }
}
#[test]
fn closed_driver_dispatches_original_failure_once_then_revokes_all_callbacks()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    runtime.block_on(async {
        type H<'owner> = Driver<'owner, 4, 32, 2, 4, 4>;
        // Only virtual MQ work is admitted. drive is first called AFTER destroy,
        // so no connect future or socket/peer/network operation is ever polled.
        let mut instance = gnunet_ipc_unix::handle::Instance::new();
        let mut h = H::new(
            &mut instance,
            "/tmp/statistics-never-opened",
            b"s",
            true,
            Limits::default(),
        )?
        .ok_or("disabled")?;
        let get = h.get(selector(b"pending"))?;
        h.destroy(false)?;
        let (mut completes, mut destroys, mut events, mut unexpected) = (0, 0, 0, 0);
        for _ in 0..4 {
            let progress = h
                .drive(None, |event, context| {
                    events += 1;
                    match event {
                        Event::GetComplete(done) => {
                            assert_eq!(destroys, 0);
                            assert_eq!(done.get, get);
                            assert!(done.result.is_err());
                            completes += 1;
                        }
                        Event::Destroyed(_) => {
                            assert_eq!(completes, 1);
                            assert_eq!(destroys, 0);
                            destroys += 1;
                        }
                        _ => unexpected += 1,
                    }
                    assert!(!context.owns_get(get));
                    assert!(!context.get_callbacks_enabled(get));
                    assert!(matches!(
                        context.set(b"late", 1, false),
                        Err(IpcError::Protocol(Error::Closed))
                    ));
                    GetFlow::Continue
                })
                .await?;
            assert!(matches!(progress, Progress::Activity | Progress::Closed));
        }
        assert_eq!((completes, destroys, events, unexpected), (1, 1, 2, 0));
        assert!(h.is_closed());
        assert!(matches!(
            h.get(selector(b"late")),
            Err(IpcError::Protocol(Error::Closed))
        ));
        assert!(!h.owns_get(get));
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}
