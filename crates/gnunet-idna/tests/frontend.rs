//! Actual55 normal-C GNUnet text/check/builder observations through the backend.
#![expect(
    clippy::unwrap_used,
    reason = "The test and oracle require exact successful fixture parsing or fail immediately."
)]
use gnunet_dns::{Arena, Name, check_label, check_name};
use gnunet_idna::{Backend, Limits, NativeProfile, Workspace};
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
#[test]
fn actual_native_gnunet_frontend_corpus_has_only_documented_safe_boundary_differences() {
    let mut count = 0;
    let mut nul_boundary = 0;
    let mut root_extra_capacity = 0;
    let mut native = Workspace::new();
    let backend = Backend::new(
        &mut native,
        Limits::GNUNET,
        NativeProfile::Libunistring1_5Unicode18_0,
    );
    for row in include_str!("frontend.tsv").lines() {
        let f: Vec<_> = row.split('\t').collect();
        assert_eq!(f.len(), 7);
        count += 1;
        let id = f[0];
        let input = unhex(f[1]);
        let label = f[2] == "1";
        let name = f[3] == "1";
        let built = f[4] == "1";
        let cap: usize = f[5].parse().unwrap();
        let wire = unhex(f[6]);
        let l = check_label(&input, &backend, &mut [0; 1024], gnunet_dns::Limits::DNS);
        let n = check_name(&input, &backend, &mut [0; 1024], gnunet_dns::Limits::DNS);
        let mut storage = [0; 1024];
        let mut arena = Arena::new(&mut storage);
        let parsed = Name::from_native_text(
            &input,
            &backend,
            &mut [0; 1024],
            &mut arena,
            gnunet_dns::Limits::DNS,
        );
        if input.contains(&0) {
            // A C string excludes its NUL terminator/trailing allocation from
            // the value. Rust's explicit native-text byte input refuses an
            // interior NUL instead of silently shortening the supplied value.
            nul_boundary += 1;
            assert_eq!(id, "raw-name-check-1");
            assert!(l.is_err() && n.is_err() && parsed.is_err());
            continue;
        }
        assert_eq!(l.is_ok(), label, "label {id}");
        assert_eq!(n.is_ok(), name, "name {id}");
        if id == "name-cap-0-1" {
            // Native root builder unnecessarily demands2 bytes for its1-byte
            // root result. The safe wire encoder accepts exact protocol size.
            root_extra_capacity += 1;
            assert!(!built);
            assert_eq!(parsed.unwrap().encode(&mut [0; 1]), Ok(1));
            continue;
        }
        let mut output = vec![0xa5; cap];
        let result = parsed.and_then(|value| value.encode(&mut output));
        assert_eq!(result.is_ok(), built, "builder {id}");
        if let Ok(n) = result {
            assert_eq!(&output[..n], wire, "wire {id}");
        } else {
            assert!(output.iter().all(|b| *b == 0xa5), "atomic error {id}");
        }
    }
    assert_eq!((count, nul_boundary, root_extra_capacity), (55, 1, 1));
}
