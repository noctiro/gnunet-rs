use crate::*;

fn bytes(value: &str) -> GnBytes {
    GnBytes {
        data: value.as_ptr(),
        len: value.len(),
    }
}

#[test]
#[expect(
    unsafe_code,
    reason = "The test owns the FFI inputs, result storage and null sentinels"
)]
fn missing_required_binding_never_transfers_a_handle() {
    let mut handle = ptr::dangling_mut();
    let options = GnNodeOptions {
        state_dir: bytes("/private/state"),
        ipc_dir: bytes("/private/ipc"),
        ..GnNodeOptions::default()
    };
    // SAFETY: options borrows the string literals and handle is an independent output slot.
    let result = unsafe { gnunet_node_start(&options, &mut handle) };
    assert_eq!(result, INVALID);
    assert!(handle.is_null());
}

#[cfg(unix)]
#[test]
#[expect(
    unsafe_code,
    reason = "The test exclusively owns its original ABI handle and local output slots"
)]
fn sdk_worker_reports_readiness_and_joins_the_original_node()
-> Result<(), Box<dyn std::error::Error>> {
    use std::{
        fs,
        os::unix::fs::DirBuilderExt,
        time::{Duration, Instant},
    };

    struct Private(std::path::PathBuf);
    impl Drop for Private {
        fn drop(&mut self) {
            let _cleanup = fs::remove_dir_all(&self.0);
        }
    }
    struct Handle(*mut GnNode);
    #[expect(
        unsafe_code,
        reason = "The fixture owns exactly one transferred SDK handle"
    )]
    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: no other owner or concurrent operation exists after fixture scope.
            unsafe {
                gnunet_node_destroy(self.0);
            }
        }
    }

    let parent = if cfg!(target_os = "macos") {
        "/private/tmp".into()
    } else {
        std::env::temp_dir()
    };
    let namespace = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let root = parent.join(format!("gn-sdk-{}-{namespace:x}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let root = Private(root);
    let config = root.0.join("gnunet.conf");
    fs::write(
        &config,
        format!(
            concat!(
                "[nat]\nUSE_STUN = NO\nENABLE_UPNP = NO\n",
                "[nse]\nWORKBITS = 0\n",
                "[communicator-udp]\nDISABLE_BROADCAST = YES\n",
                "[communicator-quic]\nBINDTO = 127.0.0.1:0\n",
                "[communicator-http3]\nBINDTO = 127.0.0.1:0\n",
                "[communicator-unix]\nUNIXPATH = {}\n",
            ),
            root.0.join("datagram").display(),
        ),
    )?;
    let directory = root.0.to_str().ok_or("SDK fixture directory encoding")?;
    let config = config.to_str().ok_or("SDK fixture config encoding")?;
    let options = GnNodeOptions {
        state_dir: bytes(directory),
        ipc_dir: bytes(directory),
        config_file: bytes(config),
        tcp_bind: bytes("127.0.0.1:0"),
        udp4_bind: bytes("127.0.0.1:0"),
        startup_timeout_ms: 5000,
        drain_timeout_ms: 1000,
        ..GnNodeOptions::default()
    };
    let mut raw = ptr::null_mut();
    // SAFETY: fields borrow live fixture strings. raw is the separate output.
    let status = unsafe { gnunet_node_start(&options, &mut raw) };
    if status != OK || raw.is_null() {
        return Err("SDK did not supply a worker".into());
    }
    let handle = Handle(raw);
    // SAFETY: the fixture retains this original live handle throughout the call.
    if unsafe { gnunet_node_notify_network_change(handle.0) } != OK {
        return Err("SDK did not accept the starting worker's network notice".into());
    }
    // SAFETY: each range and the original handle are valid for both calls.
    unsafe {
        if gnunet_node_set_dns_servers(handle.0, bytes("0.0.0.0:53")) != INVALID
            || gnunet_node_set_dns_servers(handle.0, bytes("127.0.0.1:1053")) != OK
        {
            return Err("SDK did not validate the upstream snapshot".into());
        }
    }

    for expected in [1, 3] {
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            let mut snapshot = GnNodeSnapshot::default();
            // SAFETY: the fixture retains the handle and writable snapshot for the call.
            if unsafe { gnunet_node_snapshot(handle.0, &mut snapshot) } != OK {
                return Err("SDK did not supply a snapshot".into());
            }
            if snapshot.phase == 4 {
                let mut error = [0; 4096];
                // SAFETY: live handle and independent fixed output buffer of the stated size.
                let size = unsafe { gnunet_node_error(handle.0, error.as_mut_ptr(), error.len()) };
                return Err(String::from_utf8_lossy(&error[..size.min(error.len())])
                    .into_owned()
                    .into());
            }
            if snapshot.phase == expected {
                if snapshot.has_ready != 1
                    || snapshot.tcp_port == 0
                    || snapshot.udp4_port == 0
                    || snapshot.udp6_port != 0
                    || snapshot.quic_port == 0
                    || snapshot.http3_port == 0
                    || snapshot.quic_port == snapshot.http3_port
                    || snapshot.unix_mtu == 0
                {
                    return Err("SDK did not retain actual readiness".into());
                }
                break;
            }
            if Instant::now() >= deadline {
                return Err("SDK snapshot deadline".into());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        // SAFETY: stop keeps this handle valid, including after worker retirement.
        if unsafe { gnunet_node_notify_network_change(handle.0) } != OK {
            return Err("SDK did not accept a network notice on the live handle".into());
        }
        if expected == 1 {
            // SAFETY: the live handle accepts an empty snapshot without borrowing bytes.
            if unsafe { gnunet_node_set_dns_servers(handle.0, GnBytes::default()) } != OK {
                return Err("SDK did not accept upstream revocation".into());
            }
            // SAFETY: the same original handle remains live. Stop retains ownership.
            if unsafe { gnunet_node_stop(handle.0) } != OK {
                return Err("SDK did not accept stop".into());
            }
        }
    }
    drop(handle);
    for endpoint in ["transport", "nse", "dht", "cadet", "datagram"] {
        if root.0.join(endpoint).try_exists()? {
            return Err(format!("SDK left the original {endpoint} listener open").into());
        }
    }
    Ok(())
}
