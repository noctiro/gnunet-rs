#[cfg(test)]
mod finite_io_proof {
    use super::*;
    use crate::stream::{Send, Stream};
    use gnunet_client::statistics_handle::DestroyOutcome;
    use std::sync::Arc;
    use std::task::Waker;
    type Handle<'owner> = StatisticsHandle<'owner, 8, 64, 4, 16, 8>;
    fn poll<'owner>(h: &mut Handle<'owner>) -> Poll<Result<IoEvent<'owner>, IpcError>> {
        let mut cx = Context::from_waker(Waker::noop());
        h.poll_write(&mut cx, None)
    }
    fn ready<'owner>(h: &mut Handle<'owner>) {
        assert!(matches!(poll(h), Poll::Ready(Ok(IoEvent::Activity))));
    }
    fn make<'owner>(
        instance: &'owner mut gnunet_client::statistics_handle::Instance,
        sends: impl IntoIterator<Item = Send>,
    ) -> (Handle<'owner>, Arc<std::sync::Mutex<crate::stream::State>>) {
        make_with_persistence(instance, sends, false)
    }
    fn make_with_persistence<'owner>(
        instance: &'owner mut gnunet_client::statistics_handle::Instance,
        sends: impl IntoIterator<Item = Send>,
        persistent: bool,
    ) -> (Handle<'owner>, Arc<std::sync::Mutex<crate::stream::State>>) {
        let mut h = Handle::new(
            instance,
            "/private/tmp/finite-owned-proof",
            b"s",
            true,
            Limits {
                max_frame_bytes: 64,
                write_chunk_bytes: 64,
            },
        )
        .unwrap()
        .unwrap();
        h.set(b"a", 1, persistent).unwrap();
        assert_eq!(h.core.mq_nontransmitted_length(), 1);
        let (stream, state) = Stream::scripted(sends);
        h.stream = Some(Connection::Scripted(stream));
        (h, state)
    }
    fn counters<'owner>(h: &Handle<'owner>) -> (usize, usize, bool, usize) {
        let e = &h.scheduler.envelopes[h.scheduler.head];
        (
            e.written,
            h.core.mq_nontransmitted_length(),
            e.first_attempt,
            h.core.transmit_count(),
        )
    }
    #[test]
    fn full_first_continues_without_marking_partial() {
        let mut statistics_instance_1 = gnunet_client::statistics_handle::Instance::new();
        let (mut h, state) = make(&mut statistics_instance_1, [Send::Bytes(20)]);
        ready(&mut h);
        assert_eq!(counters(&h), (0, 0, false, 0));
        assert_eq!(state.lock().unwrap().accepted.len(), 20);
        println!(
            "normalized-io|full|0|{}|{}|{}|{}|0",
            state.lock().unwrap().accepted.len(),
            h.core.mq_nontransmitted_length(),
            u8::from(h.scheduler.envelopes[h.scheduler.head].first_attempt),
            u8::from(h.core.transmit_count() == 0)
        );
        h.destroy(false).unwrap();
        let report = h.core.take_destroy_report().unwrap();
        assert_eq!(report.outcome, DestroyOutcome::Discarded);
        assert_eq!(report.unconfirmed_mutations, 1);
    }
    #[test]
    fn partial_zero_eagain_eintr_preserve_front_and_mark_only_once() {
        for (name, first, n) in [
            ("partial", Send::Bytes(3), 3),
            ("zero", Send::Bytes(0), 0),
            ("eagain", Send::Error(io::ErrorKind::WouldBlock), 0),
            ("eintr", Send::Error(io::ErrorKind::Interrupted), 0),
        ] {
            let mut statistics_instance_2 = gnunet_client::statistics_handle::Instance::new();
            let (mut h, state) = make(
                &mut statistics_instance_2,
                [
                    first,
                    Send::Bytes(0),
                    Send::Error(io::ErrorKind::WouldBlock),
                    Send::Error(io::ErrorKind::Interrupted),
                    Send::Bytes(20 - n),
                ],
            );
            let original = h.scheduler.envelopes[0].bytes[..20].to_vec();
            for i in 0..4 {
                ready(&mut h);
                assert_eq!(counters(&h), (n, 0, true, 1));
                assert_eq!(&h.scheduler.envelopes[0].bytes[..20], &original);
                assert_eq!(
                    state.lock().unwrap().calls[i],
                    original[if i == 0 { 0 } else { n }..]
                );
                println!(
                    "normalized-io|{name}|{i}|{}|{}|{}|{}|0",
                    state.lock().unwrap().accepted.len(),
                    h.core.mq_nontransmitted_length(),
                    u8::from(h.scheduler.envelopes[h.scheduler.head].first_attempt),
                    u8::from(h.core.transmit_count() == 0)
                );
            }
            ready(&mut h);
            assert_eq!(counters(&h), (0, 0, false, 0));
            assert_eq!(state.lock().unwrap().accepted, original);
            println!(
                "normalized-io|{name}|4|{}|{}|{}|{}|0",
                state.lock().unwrap().accepted.len(),
                h.core.mq_nontransmitted_length(),
                u8::from(h.scheduler.envelopes[h.scheduler.head].first_attempt),
                u8::from(h.core.transmit_count() == 0)
            );
            h.destroy(false).unwrap();
            let report = h.core.take_destroy_report().unwrap();
            assert_eq!(report.unconfirmed_mutations, 1);
            assert_eq!(report.outcome, DestroyOutcome::Discarded);
        }
    }
    #[test]
    fn readiness_pending_wait_deadline_and_cancelled_drive_do_not_start_an_attempt() {
        let mut statistics_instance_3 = gnunet_client::statistics_handle::Instance::new();
        let (mut h, state) = make(&mut statistics_instance_3, [Send::Bytes(20)]);
        state.lock().unwrap().ready = false;
        assert!(poll(&mut h).is_pending());
        assert_eq!(counters(&h), (0, 1, false, 1));
        assert!(state.lock().unwrap().calls.is_empty());
        let mut cx = Context::from_waker(Waker::noop());
        assert!(matches!(
            h.poll_write(&mut cx, Some(Instant::now())),
            Poll::Ready(Ok(IoEvent::WaitDeadline))
        ));
        assert_eq!(counters(&h), (0, 1, false, 1));
        let mut drive = Box::pin(h.drive(None, |_, _| GetFlow::Continue));
        assert!(drive.as_mut().poll(&mut cx).is_pending());
        drop(drive);
        assert_eq!(counters(&h), (0, 1, false, 1));
        assert!(state.lock().unwrap().calls.is_empty());
        state.lock().unwrap().ready = true;
        ready(&mut h);
        assert_eq!(state.lock().unwrap().accepted.len(), 20);
    }
    #[test]
    fn fatal_first_epipe_never_marks_inflight_or_admits_second_mutation() {
        let mut statistics_instance_4 = gnunet_client::statistics_handle::Instance::new();
        let (mut h, state) = make_with_persistence(
            &mut statistics_instance_4,
            [Send::Error(io::ErrorKind::BrokenPipe)],
            true,
        );
        h.set(b"b", 2, false).unwrap();
        let old = h.core.connection_epoch().unwrap();
        assert_eq!(h.core.pending_actions(), 1);
        assert_eq!(h.scheduler.len, 1);
        assert!(matches!(poll(&mut h),Poll::Ready(Ok(IoEvent::Lost(e,Error::Io)))if e==old));
        assert!(h.core.connection_epoch().is_none());
        // Old immutable storage may remain until the next epoch or close.
        // It has no socket/epoch authority and cannot issue another send.
        assert!(h.stream.is_none());
        assert!(h.io_epoch.is_none());
        assert!(poll(&mut h).is_pending());
        assert_eq!(state.lock().unwrap().calls.len(), 1);
        assert_eq!(h.core.transmit_count(), 0);
        assert_eq!(h.core.pending_actions(), 1);
        println!(
            "normalized-owner-fatal-first|{}|{}",
            u8::from(h.core.connection_epoch().is_some()),
            h.core.pending_actions()
        );
        assert_eq!(state.lock().unwrap().calls.len(), 1);
        assert!(state.lock().unwrap().accepted.is_empty());
        assert_eq!(h.take_io_error().unwrap().kind(), io::ErrorKind::BrokenPipe);
        h.destroy(false).unwrap();
        let report = h.core.take_destroy_report().unwrap();
        assert_eq!(
            report,
            DestroyReport {
                outcome: DestroyOutcome::Discarded,
                queued_mutations_discarded: 1,
                unconfirmed_mutations: 1,
                unconfirmed_persistent_mutations: 1
            }
        );
    }
    #[test]
    fn ready_error_is_not_a_send_attempt() {
        let mut statistics_instance_5 = gnunet_client::statistics_handle::Instance::new();
        let (mut h, state) = make(&mut statistics_instance_5, [Send::Bytes(20)]);
        state.lock().unwrap().readiness_error = Some(io::ErrorKind::BrokenPipe);
        assert!(matches!(
            poll(&mut h),
            Poll::Ready(Ok(IoEvent::Lost(_, Error::Io)))
        ));
        assert!(state.lock().unwrap().calls.is_empty());
        h.destroy(false).unwrap();
        assert_eq!(
            h.core.take_destroy_report().unwrap().unconfirmed_mutations,
            1
        );
    }
    #[test]
    fn first_partial_admits_only_second_immutable_copy_and_keeps_third_pending() {
        let mut statistics_instance_6 = gnunet_client::statistics_handle::Instance::new();
        let (mut h, state) = make(
            &mut statistics_instance_6,
            [
                Send::Bytes(3),
                Send::Bytes(17),
                Send::Bytes(20),
                Send::Bytes(20),
            ],
        );
        h.set(b"b", 2, false).unwrap();
        let original = h.scheduler.envelopes[0].bytes[..20].to_vec();
        assert_eq!(h.scheduler.len, 1);
        ready(&mut h);
        assert_eq!(counters(&h), (3, 1, true, 2));
        assert_eq!(h.scheduler.len, 2);
        let second = h.scheduler.envelopes[1].bytes[..20].to_vec();
        assert_eq!(&second[8..16], &2u64.to_be_bytes());
        h.set(b"b", 3, true).unwrap();
        assert_eq!(h.core.pending_actions(), 1);
        assert_eq!(&h.scheduler.envelopes[0].bytes[..20], &original);
        assert_eq!(&h.scheduler.envelopes[1].bytes[..20], &second);
        println!(
            "immutable|partial|{}|{}|{}|{}",
            h.scheduler.envelopes[h.scheduler.head].written,
            h.core.mq_nontransmitted_length(),
            h.core.pending_actions(),
            u64::from_be_bytes(
                h.scheduler.envelopes[h.scheduler.head].bytes[8..16]
                    .try_into()
                    .unwrap()
            )
        );
        ready(&mut h);
        assert_eq!(h.scheduler.head, 1);
        assert_eq!(h.scheduler.envelopes[1].written, 0);
        assert_eq!(state.lock().unwrap().accepted, original);
        println!(
            "immutable|second|{}|{}|{}",
            h.scheduler.envelopes[h.scheduler.head].written,
            h.core.mq_nontransmitted_length(),
            u64::from_be_bytes(
                h.scheduler.envelopes[h.scheduler.head].bytes[8..16]
                    .try_into()
                    .unwrap()
            )
        );
        ready(&mut h);
        assert_eq!(h.core.pending_actions(), 0);
        assert_eq!(h.scheduler.len, 1);
        let third = h.scheduler.envelopes[h.scheduler.head].bytes[..20].to_vec();
        assert_eq!(&third[8..16], &3u64.to_be_bytes());
        assert_eq!(&third[4..8], &2u32.to_be_bytes());
        ready(&mut h);
        assert_eq!(
            state.lock().unwrap().accepted,
            [original, second, third].concat()
        );
        h.destroy(false).unwrap();
        assert_eq!(
            h.core.take_destroy_report().unwrap().unconfirmed_mutations,
            3
        );
    }
    #[test]
    fn dropping_drive_after_partial_preserves_both_original_cursors() {
        let mut statistics_instance_7 = gnunet_client::statistics_handle::Instance::new();
        let (mut h, state) = make(
            &mut statistics_instance_7,
            [Send::Bytes(3), Send::Bytes(17)],
        );
        ready(&mut h);
        let original = h.scheduler.envelopes[h.scheduler.head].bytes[..20].to_vec();
        state.lock().unwrap().ready = false;
        let mut cx = Context::from_waker(Waker::noop());
        let mut drive = Box::pin(h.drive(None, |_, _| GetFlow::Continue));
        assert!(drive.as_mut().poll(&mut cx).is_pending());
        drop(drive);
        assert_eq!(counters(&h), (3, 0, true, 1));
        assert_eq!(
            &h.scheduler.envelopes[h.scheduler.head].bytes[..20],
            &original
        );
        state.lock().unwrap().ready = true;
        ready(&mut h);
        assert_eq!(state.lock().unwrap().accepted, original);
    }
}

#[cfg(test)]
mod port_proof {
    use super::*;
    use crate::resolution::{AddressLookup, PortError, ResolutionContext, ResolutionTimer};
    use gnunet_service_runtime::clock::{ClockSample, ClockSubscription, RuntimeClock};
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Default)]
    struct Clock {
        waiters: Arc<AtomicUsize>,
    }
    struct Waiter(Arc<AtomicUsize>);
    impl Drop for Waiter {
        fn drop(&mut self) {
            self.0.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl ClockSubscription for Waiter {
        fn poll_changed(
            &mut self,
            _: &mut Context<'_>,
            _: u64,
        ) -> Poll<Result<ClockSample, Error>> {
            Poll::Pending
        }
    }
    impl RuntimeClock for Clock {
        fn sample(&self) -> Result<ClockSample, Error> {
            Ok(ClockSample {
                now: AbsoluteTime::from_micros(77),
                revision: 0,
            })
        }
        fn subscribe(&self) -> Result<Box<dyn ClockSubscription>, Error> {
            self.waiters.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(Waiter(self.waiters.clone())))
        }
    }
    struct Resolution {
        clock: Arc<Clock>,
        timers: AtomicUsize,
        lookups: AtomicUsize,
    }
    impl ResolutionContext for Resolution {
        fn clock(&self) -> Arc<dyn RuntimeClock> {
            self.clock.clone()
        }
        fn lookup(&self, _: &[u8], _: Duration) -> io::Result<Option<Box<dyn AddressLookup>>> {
            self.lookups.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::other(
                "this Unix-only test has no DNS callback provider",
            ))
        }
        fn timer(&self, duration: Duration) -> io::Result<ResolutionTimer> {
            assert_eq!(duration, Duration::from_micros(17));
            self.timers.fetch_add(1, Ordering::SeqCst);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "original caller timer refusal",
            ))
        }
    }
    fn resolution() -> Arc<Resolution> {
        Arc::new(Resolution {
            clock: Arc::new(Clock::default()),
            timers: AtomicUsize::new(0),
            lookups: AtomicUsize::new(0),
        })
    }
    type Handle<'owner> = StatisticsHandle<'owner, 8, 64, 4, 16, 8>;
    #[test]
    fn configured_and_live_owners_share_source_but_keep_distinct_waiters_and_timer_port() {
        let context = resolution();
        let expected: Arc<dyn RuntimeClock> = context.clock.clone();
        let mut a = Instance::new();
        let mut b = Instance::new();
        let mut first = Handle::from_config(
            &mut a,
            &Configuration::default(),
            context.clone(),
            b"s",
            Limits::default(),
        )
        .unwrap()
        .unwrap();
        let live = crate::LiveConfiguration::new(Configuration::default());
        let mut second =
            Handle::from_live_config(&mut b, live, context.clone(), b"s", Limits::default())
                .unwrap()
                .unwrap();
        assert!(Arc::ptr_eq(&first.clock_source, &expected));
        assert!(Arc::ptr_eq(&second.clock_source, &expected));
        assert_eq!(
            clock_now(&first.clock_source).unwrap(),
            AbsoluteTime::from_micros(77)
        );
        assert_eq!(context.clock.waiters.load(Ordering::SeqCst), 2);
        assert_eq!(context.lookups.load(Ordering::SeqCst), 0);
        let error = match first.scheduler.source.timer(Duration::from_micros(17)) {
            Ok(_) => panic!("timer must preserve caller refusal"),
            Err(e) => e,
        };
        let marked = PortError::from_io(&error).unwrap();
        assert_eq!(marked.cause().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(marked.cause().to_string(), "original caller timer refusal");
        assert_eq!(context.timers.load(Ordering::SeqCst), 1);
        first.destroy(false).unwrap();
        assert_eq!(context.clock.waiters.load(Ordering::SeqCst), 1);
        second.destroy(false).unwrap();
        assert_eq!(context.clock.waiters.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn live_endpoint_uses_actual_client_and_rereads_unixpath_at_attempt() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            struct OwnedDirectory(std::path::PathBuf);
            impl Drop for OwnedDirectory {
                fn drop(&mut self) {
                    let _ = std::fs::remove_dir_all(&self.0);
                }
            }
            let root = std::env::temp_dir().join(format!(
                "gnunet-clock-port-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir(&root).unwrap();
            let owned = OwnedDirectory(root);
            let original = owned.0.join("old");
            let replacement = owned.0.join("new");
            let listener = tokio::net::UnixListener::bind(&replacement).unwrap();
            let mut cfg = Configuration::default();
            cfg.set_value(
                b"statistics",
                b"UNIXPATH",
                Some(original.as_os_str().as_encoded_bytes()),
            )
            .unwrap();
            let live = crate::LiveConfiguration::new(cfg);
            let context = resolution();
            let source = Source::live(live.clone(), b"statistics", context.clone());
            let endpoint = source.resolve().unwrap();
            let mut cfg = Configuration::default();
            cfg.set_value(
                b"statistics",
                b"UNIXPATH",
                Some(replacement.as_os_str().as_encoded_bytes()),
            )
            .unwrap();
            live.replace(cfg).unwrap();
            let connection = tokio::time::timeout(Duration::from_secs(2), endpoint.attempt(0))
                .await
                .unwrap()
                .unwrap();
            assert!(matches!(connection, Connection::Native(_)));
            let (accepted, _) = listener.accept().await.unwrap();
            drop(connection);
            drop(accepted);
            assert_eq!(context.lookups.load(Ordering::SeqCst), 0);
            assert_eq!(context.timers.load(Ordering::SeqCst), 0);
            assert!(!original.exists());
        });
    }
}
