use super::{Bounds, DnsLimits, Instant, RecursiveDns, Run};
use gnunet_service_runtime::clock::SystemClock;
use gnunet_types::AbsoluteTime;
use std::{error::Error, fs, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

struct Fixture(PathBuf);

impl Drop for Fixture {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "assert snapshot identities while propagating setup and file errors"
)]
fn bootstrap_refreshes_for_new_operations_and_keeps_the_original_snapshot()
-> Result<(), Box<dyn Error>> {
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce)?;
    let directory = std::env::temp_dir().join(format!(
        "gnunet-test-dns-bootstrap-{:016x}",
        u64::from_ne_bytes(nonce)
    ));
    fs::create_dir(&directory)?;
    let fixture = Fixture(directory);
    let path = fixture.0.join("resolv.conf");
    let dns =
        RecursiveDns::from_resolv_conf(Arc::new(SystemClock), &path, 1024, DnsLimits::default())?;
    let bounds = Bounds::new(
        AbsoluteTime::from_micros(u64::MAX - 1),
        Instant::now() + Duration::from_secs(30),
    )?;
    assert!(Run::new(dns.shared.clone(), bounds).bootstrap().is_err());

    fs::write(&path, "nameserver 127.0.0.1\n")?;
    let first = Run::new(dns.shared.clone(), bounds);
    let first_server = SocketAddr::from(([127, 0, 0, 1], 53));
    assert_eq!(first.bootstrap()?, &[first_server]);

    fs::write(&path, "nameserver 127.0.0.2\n")?;
    let second_server = SocketAddr::from(([127, 0, 0, 2], 53));
    assert_eq!(Run::new(dns.shared, bounds).bootstrap()?, &[second_server]);
    assert_eq!(first.bootstrap()?, &[first_server]);
    Ok(())
}
