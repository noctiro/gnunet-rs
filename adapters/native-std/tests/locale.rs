//! Native locale ownership and exact bounded readers; no process locale mutation.
use gnunet_native::locale::{CaseContext, CaseSnapshot, LocaleSnapshot};
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "All byte/C-string-prefix and space-class outcomes are independent literal assertions"
)]
fn c_snapshot_reads_bounded_spans_nuls_and_all_byte_classes_without_terminator()
-> std::io::Result<()> {
    let native = LocaleSnapshot::named(b"C")?;
    assert!(native.equals(b"", b"\0suffix"));
    assert!(native.equals(b"A\0left", b"a\0right"));
    assert!(!native.equals(b"A", b"a longer"));
    for value in 0..=255u8 {
        let a = [value];
        let b = [value.to_ascii_uppercase()];
        assert!(native.equals(&a, &b));
        assert_eq!(
            native.is_space(value),
            matches!(value, b' ' | b'\t'..=b'\r')
        );
    }
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Conversions use the defined native strto* interfaces, never an overflowing scanf oracle"
)]
fn defined_native_scan_keeps_consumption_range_and_signed_zero_explicit() -> std::io::Result<()> {
    let native = LocaleSnapshot::named(b"C")?;
    let scan = native.scan_float(b"\x0b1.25 \t")?;
    assert_eq!(scan.value, 1.25);
    assert_eq!(scan.consumed, 5);
    assert!(!scan.range_error);
    assert_eq!(
        native.scan_float(b"-0.0")?.value.to_bits(),
        (-0.0f32).to_bits()
    );
    assert!(native.scan_float(b"1e10000")?.range_error);
    assert!(native.scan_float(b"1e-10000")?.range_error);
    let scan = native.scan_number(b" -1 trailing")?;
    assert_eq!(scan.value, u64::MAX);
    assert_eq!(scan.consumed, 3);
    assert!(!scan.range_error);
    assert!(native.scan_number(b"18446744073709551616")?.range_error);
    Ok(())
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "A failed named locale leaves the prior shared selection intact and retained snapshots remain usable after context Drop"
)]
fn context_replacement_is_atomic_and_retained_selection_outlives_context() -> std::io::Result<()> {
    fn require<T: Send + Sync>() {}
    require::<LocaleSnapshot>();
    require::<CaseContext>();
    let context = CaseContext::c();
    let shared = context.clone();
    assert!(
        shared
            .replace_named(b"owned-gnunet-locale-never-installed-0726")
            .is_err()
    );
    assert!(matches!(context.snapshot(), CaseSnapshot::C));
    let old = context.replace(CaseSnapshot::Native(LocaleSnapshot::named(b"C")?));
    assert!(matches!(old, CaseSnapshot::C));
    let retained = shared.snapshot();
    drop(context);
    drop(shared);
    assert!(retained.equals(b"retained", b"RETAINED"));
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Actual thread-local native effect plus duplicate ownership is verified after the original thread exits"
)]
fn current_thread_failure_keeps_owned_locale_and_snapshot_outlives_thread_exit()
-> std::io::Result<()> {
    fn require<T: Send + Sync>() {}
    require::<gnunet_native::locale::ThreadLocale>();
    require::<CaseContext>();
    // SAFETY: this test never mutates global locale. The other native tests use
    // immutable *_l readers only, and this thread owns all installed private
    // locale effects without exposing native pointers to foreign code.
    #[expect(
        unsafe_code,
        reason = "Finite test certifies no native global mutation and no raw locale pointer escape"
    )]
    // SAFETY: no global locale is mutated and no native private pointer escapes.
    let token = unsafe { gnunet_native::locale::ThreadLocale::acquire()? };
    let worker = std::thread::spawn(move || -> std::io::Result<_> {
        let failed = token.configuration_float(b"owned-not-a-float")?;
        if failed.matched || failed.range_error {
            return Err(std::io::Error::other(
                "defined lexical failure was not preserved",
            ));
        }
        let retained = token.snapshot()?;
        // Repeated failed operations replace/free their old private TLS owner;
        // the independent duplicate remains a valid native reader.
        for _ in 0..64 {
            let result = token.configuration_float(b"owned-failure")?;
            if result.matched {
                return Err(std::io::Error::other("lexical failure accepted"));
            }
        }
        Ok(retained)
    });
    let retained = worker
        .join()
        .map_err(|_| std::io::Error::other("native worker panicked"))??;
    assert_eq!(retained.scan_float(b"1.25")?.value, 1.25);
    assert_eq!(retained.scan_float(b"1,5")?.consumed, 1);
    Ok(())
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "A late destructor cannot install an owner into destroyed TLS or leave a freed locale selected"
)]
fn float_failure_during_late_tls_destructor_returns_boundary_error_without_fake_success()
-> std::io::Result<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    struct Late {
        token: gnunet_native::locale::ThreadLocale,
        observed: Arc<AtomicUsize>,
    }
    impl Drop for Late {
        fn drop(&mut self) {
            let result = self.token.configuration_float(b"late-lexical-failure");
            self.observed
                .store(if result.is_err() { 1 } else { 2 }, Ordering::SeqCst);
        }
    }
    std::thread_local! {static LATE:std::cell::RefCell<Option<Late>>=const{std::cell::RefCell::new(None)};}
    let observed = Arc::new(AtomicUsize::new(0));
    let received = observed.clone();
    let worker = std::thread::spawn(move || -> std::io::Result<()> {
        // SAFETY: this worker performs no global locale mutation and retains no
        // private pointer; its reader capability is owned through thread exit.
        #[expect(
            unsafe_code,
            reason = "Dedicated worker has only owned synchronous native locale effects and no global mutation"
        )]
        // SAFETY: no global locale is mutated and no native private pointer escapes.
        let token = unsafe { gnunet_native::locale::ThreadLocale::acquire()? };
        // Initialized first, so this runs after the installed-locale TLS owner.
        LATE.with(|slot| {
            *slot.borrow_mut() = Some(Late {
                token: token.clone(),
                observed: received,
            });
        });
        let result = token.configuration_float(b"first-lexical-failure")?;
        if result.matched {
            return Err(std::io::Error::other("lexical failure accepted"));
        }
        Ok(())
    });
    worker
        .join()
        .map_err(|_| std::io::Error::other("destructor worker panicked"))??;
    assert_eq!(observed.load(Ordering::SeqCst), 1);
    Ok(())
}
