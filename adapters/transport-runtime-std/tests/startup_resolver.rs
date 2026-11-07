//! The foreground owns and drives the real process Resolver while identity waits.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Independent actual Unix query and END assertions verify reactor completion"
)]
use gnunet_config::Configuration;
use gnunet_service_runtime::Activation;
use gnunet_transport_runtime::{
    Limits, LocalKeyCapability,
    startup::{self, LocalStartup},
};
use std::{
    error::Error,
    path::PathBuf,
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}
#[tokio::test(flavor = "current_thread")]
async fn pending_identity_does_not_repoll_completed_original_resolver_future()
-> Result<(), Box<dyn Error>> {
    let d = Directory(std::env::temp_dir().join(format!(
        "gnrs-tr-start-resolver-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::SeqCst)
    )));
    std::fs::create_dir(&d.0)?;
    let resolver_path = d.0.join("resolver");
    let listener = UnixListener::bind(&resolver_path)?;
    let mut cfg = Configuration::default();
    for (section, path) in [
        (b"resolver".as_slice(), resolver_path),
        (b"transport", d.0.join("transport")),
        (b"peerstore", d.0.join("peerstore")),
    ] {
        cfg.set_value(
            section,
            b"UNIXPATH",
            Some(path.as_os_str().as_encoded_bytes()),
        )?;
    }
    cfg.set_value(
        b"pils",
        b"HOSTNAME",
        Some(b"original-identity-lookup.invalid"),
    )?;
    cfg.set_value(b"pils", b"PORT", Some(b"1"))?;
    let seen = AtomicBool::new(false);
    let announced = AtomicBool::new(false);
    let resolver = async {
        let (mut stream, _) = listener.accept().await?;
        let mut header = [0; 4];
        stream.read_exact(&mut header).await?;
        let size = usize::from(u16::from_be_bytes([header[0], header[1]]));
        assert!((17..=65535).contains(&size));
        let mut request = vec![0; size];
        request[..4].copy_from_slice(&header);
        stream.read_exact(&mut request[4..]).await?;
        assert_eq!(&header[2..], &4_u16.to_be_bytes());
        assert_eq!(&request[16..], b"original-identity-lookup.invalid\0");
        // Official RESOLVER_RESPONSE(5): unchanged opaque four-byte ID and no
        // payload is the genuine END; it is not an address or a PILS reply.
        let mut end = [0_u8; 8];
        end[..2].copy_from_slice(&8_u16.to_be_bytes());
        end[2..4].copy_from_slice(&5_u16.to_be_bytes());
        end[4..].copy_from_slice(&request[12..16]);
        stream.write_all(&end).await?;
        seen.store(true, Ordering::SeqCst);
        assert_eq!(stream.read(&mut [0]).await?, 0);
        Ok::<_, Box<dyn Error>>(())
    };
    let service = startup::foreground_local(
        LocalStartup {
            config: &cfg,
            activation: Activation::default(),
            state_directory: d.0.join("state"),
            local_key: LocalKeyCapability {
                ikm_file: d.0.join("unused-key"),
            },
            limits: Limits::default(),
        },
        |_, _, _| {
            announced.store(true, Ordering::SeqCst);
            Ok(())
        },
        async {
            tokio::time::sleep(Duration::from_millis(250)).await;
            Ok(())
        },
        |_| {},
        |_| {},
    );
    let (report, response) = tokio::time::timeout(Duration::from_secs(3), async {
        tokio::join!(service, resolver)
    })
    .await?;
    response?;
    assert_eq!(report?.activations, 0);
    assert!(seen.load(Ordering::SeqCst));
    assert!(!announced.load(Ordering::SeqCst));
    Ok(())
}
