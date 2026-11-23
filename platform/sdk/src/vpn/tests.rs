use super::protection::gnunet_node_start_with_protected_vpn;
use super::*;
use gnunet_wire::official::{
    RelativeTime,
    dht::ipc as dht,
    regex::{Request, SearchResult, StringBytes},
};
use std::{
    ffi::c_void,
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt},
        net::UnixStream,
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _cleaned = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct Handles {
    node: *mut GnNode,
    vpn: *mut GnVpn,
}

impl Drop for Handles {
    fn drop(&mut self) {
        // SAFETY: these are the exclusive startup handles; no borrows remain.
        unsafe {
            gnunet_vpn_destroy(self.vpn);
            crate::gnunet_node_destroy(self.node);
        }
    }
}

fn bytes(text: &str) -> GnBytes {
    GnBytes {
        data: text.as_ptr(),
        len: text.len(),
    }
}

fn check(result: i32) -> io::Result<()> {
    if result == OK {
        return Ok(());
    }
    Err(io::Error::other(format!(
        "VPN fixture received status {result}"
    )))
}

#[test]
fn embedded_worker_requires_exact_vpn_routes_and_has_no_peer_listener()
-> Result<(), Box<dyn std::error::Error>> {
    run_embedded_worker(None)
}

#[derive(Default)]
struct Probe {
    protected: AtomicUsize,
    released: AtomicUsize,
}

impl Probe {
    fn context(self: &Arc<Self>) -> GnSocketProtection {
        GnSocketProtection {
            context: Arc::into_raw(self.clone()).cast_mut().cast(),
            protect: Some(count_protection),
            release: Some(release_probe),
        }
    }
}

unsafe extern "C" fn count_protection(context: *mut c_void, socket: i32) -> i32 {
    // SAFETY: this original context owns an Arc reference through the borrowed call.
    let probe = unsafe { &*context.cast::<Probe>() };
    if socket < 0 {
        return 0;
    }
    probe.protected.fetch_add(1, Ordering::Relaxed);
    1
}

unsafe extern "C" fn release_probe(context: *mut c_void) {
    // SAFETY: context was transferred as one Arc reference and this is its
    // original final release, after all protection callbacks retired.
    let probe = unsafe { Arc::from_raw(context.cast::<Probe>()) };
    probe.released.fetch_add(1, Ordering::Relaxed);
}

#[test]
fn rejected_start_releases_the_original_protection_context() -> io::Result<()> {
    let probe = Arc::new(Probe::default());
    let protection = probe.context();
    let mut handles = Handles::default();
    // SAFETY: only the protection input is present; it transfers one valid
    // Arc reference. Handle output slots are independent and writable.
    let status = unsafe {
        gnunet_node_start_with_protected_vpn(
            ptr::null(),
            ptr::null(),
            &protection,
            &mut handles.node,
            &mut handles.vpn,
        )
    };
    if status != INVALID
        || !handles.node.is_null()
        || !handles.vpn.is_null()
        || probe.released.load(Ordering::Relaxed) != 1
        || probe.protected.load(Ordering::Relaxed) != 0
    {
        return Err(io::Error::other(
            "rejected startup did not retire its original protection",
        ));
    }
    Ok(())
}

#[test]
fn protected_worker_uses_one_original_context_for_peer_socket_families()
-> Result<(), Box<dyn std::error::Error>> {
    let probe = Arc::new(Probe::default());
    run_embedded_worker(Some(&probe))?;
    if probe.protected.load(Ordering::Relaxed) < 4 || probe.released.load(Ordering::Relaxed) != 1 {
        return Err(
            "protected worker omitted a peer socket or leaked its protection context".into(),
        );
    }
    Ok(())
}

fn run_embedded_worker(probe: Option<&Arc<Probe>>) -> Result<(), Box<dyn std::error::Error>> {
    let timestamp = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?;
    let parent: PathBuf = if cfg!(target_os = "macos") {
        "/private/tmp".into()
    } else {
        std::env::temp_dir()
    };
    let root = parent.join(format!(
        "gn-vpn-{}-{}",
        std::process::id(),
        timestamp.subsec_nanos()
    ));
    fs::DirBuilder::new().mode(0o700).create(&root)?;
    let root = Scratch(root);
    let config = root.0.join("test.conf");
    let mut config_text = String::from("[nat]\nUSE_STUN=NO\nENABLE_UPNP=NO\n[nse]\nWORKBITS=0\n");
    if probe.is_some() {
        config_text.push_str(
            "[communicator-udp]\nDISABLE_BROADCAST=YES\n[communicator-quic]\nBINDTO=127.0.0.1:0\n[communicator-http3]\nBINDTO=127.0.0.1:0\n",
        );
    }
    fs::write(&config, config_text)?;
    let directory = root.0.to_str().ok_or("fixture directory is not UTF-8")?;
    let config = config.to_str().ok_or("fixture config is not UTF-8")?;
    let options = GnNodeOptions {
        state_dir: bytes(directory),
        ipc_dir: bytes(directory),
        config_file: bytes(config),
        tcp_bind: probe.map_or_else(GnBytes::default, |_| bytes("127.0.0.1:0")),
        udp4_bind: probe.map_or_else(GnBytes::default, |_| bytes("127.0.0.1:0")),
        startup_timeout_ms: 6000,
        drain_timeout_ms: 1000,
        ..GnNodeOptions::default()
    };
    let vpn_options = GnVpnOptions {
        peer_mode: if probe.is_some() { 1 } else { 2 },
        packet_source: 1,
        maximum_packet: 1500,
        ingress_packets: 2,
    };
    let mut handles = Handles::default();
    // SAFETY: options borrow the two owned path strings; both handle slots are distinct.
    check(unsafe {
        if let Some(probe) = probe {
            gnunet_node_start_with_protected_vpn(
                &options,
                &vpn_options,
                &probe.context(),
                &mut handles.node,
                &mut handles.vpn,
            )
        } else {
            gnunet_node_start_with_vpn(&options, &vpn_options, &mut handles.node, &mut handles.vpn)
        }
    })?;
    let mut packet = [0; 1500];
    let mut command = GnVpnCommand::default();
    // SAFETY: the fixture owns both handles and lends independent writable buffers.
    unsafe {
        check(gnunet_vpn_next(
            handles.vpn,
            4000,
            &mut command,
            packet.as_mut_ptr(),
            packet.len(),
        ))?;
        if command.kind != 1 || command.mtu != 1280 || command.ipv4.family != 4 {
            return Err("expected an original, complete install plan".into());
        }
        let regex = root.0.join("regex");
        if !fs::symlink_metadata(&regex)?.file_type().is_socket() {
            return Err("VPN requested routes before its private REGEX listener".into());
        }
        let install = command.token;
        let mut snapshot = crate::GnNodeSnapshot::default();
        check(crate::gnunet_node_snapshot(handles.node, &mut snapshot))?;
        if snapshot.has_ready != 0 {
            return Err("node reported readiness before the original route receipt".into());
        }
        let wrong = GnVpnToken {
            revision: install.revision + 1,
            ..install
        };
        if gnunet_vpn_route_complete(handles.vpn, wrong, 1, GnBytes::default()) != INVALID {
            return Err("an unclaimed route revision was accepted".into());
        }
        check(gnunet_vpn_route_complete(
            handles.vpn,
            install,
            1,
            GnBytes::default(),
        ))?;
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        loop {
            check(crate::gnunet_node_snapshot(handles.node, &mut snapshot))?;
            if snapshot.has_ready != 0 {
                break;
            }
            if snapshot.phase == 4 || std::time::Instant::now() >= deadline {
                let mut error = [0; 4096];
                let count = crate::gnunet_node_error(handles.node, error.as_mut_ptr(), error.len());
                return Err(format!(
                    "VPN worker did not become ready: {}",
                    String::from_utf8_lossy(&error[..count.min(error.len())])
                )
                .into());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        if probe.is_some() {
            if [
                snapshot.tcp_port,
                snapshot.udp4_port,
                snapshot.quic_port,
                snapshot.http3_port,
            ]
            .contains(&0)
            {
                return Err("protected listening worker missed a configured communicator".into());
            }
            check_regex_exit_lookup(&root.0, &*handles.vpn, snapshot.peer)?;
        } else if snapshot.tcp_port != 0 || snapshot.udp4_port != 0 || snapshot.udp6_port != 0 {
            return Err("outbound TCP mode exposed a network listener".into());
        }
        check(crate::gnunet_node_stop(handles.node))?;
        check(gnunet_vpn_next(
            handles.vpn,
            4000,
            &mut command,
            packet.as_mut_ptr(),
            packet.len(),
        ))?;
        if command.kind != 2
            || command.token.epoch != install.epoch
            || command.token.revision <= install.revision
        {
            return Err("stop did not request removal of the original routes".into());
        }
        if !regex.try_exists()? {
            return Err("REGEX stopped before the VPN removed its routes".into());
        }
        check(gnunet_vpn_route_complete(
            handles.vpn,
            command.token,
            2,
            GnBytes::default(),
        ))?;
        check(gnunet_vpn_next(
            handles.vpn,
            4000,
            &mut command,
            packet.as_mut_ptr(),
            packet.len(),
        ))?;
        if command.kind != 4 {
            return Err("provider did not retire after actual removal receipt".into());
        }
    }
    drop(handles);
    for service in ["vpn", "cadet", "regex", "dht", "pils"] {
        if root.0.join(service).try_exists()? {
            return Err(format!("private {service} IPC survived worker retirement").into());
        }
    }
    Ok(())
}

fn check_regex_exit_lookup(
    ipc: &Path,
    vpn: &GnVpn,
    expected_peer: [u8; 32],
) -> Result<(), Box<dyn std::error::Error>> {
    let destination = Address::V4([192, 0, 2, 1]);
    let term = b"GNUNET-VPN-VER-0001-4-01BB-C0000201";
    let (_, first_key) = gnunet_regex::first_key(term);
    let mut monitor = service_stream(ipc, "dht")?;
    let mut request = [0; 128];
    let size = dht::Monitor {
        block_type: 22,
        get: 1,
        get_response: 0,
        put: 0,
        key: Some(&first_key),
    }
    .encode(false, &mut request)?;
    monitor.write_all(&request[..size])?;
    let size = dht::encode_hello(None, true, &mut request)?;
    monitor.write_all(&request[..size])?;
    if !matches!(
        dht::Request::decode(&read_frame(&mut monitor)?)?,
        dht::Request::HelloUrl(_)
    ) {
        return Err("DHT never processed the monitor connection".into());
    }

    let mut control = service_stream(ipc, "vpn")?;
    let expires = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_micros()
        + 30_000_000;
    let request_id = [1; 8];
    let size = gnunet_vpn::WireRequest::Internet {
        reserved: 0,
        expires: u64::try_from(expires)?,
        result_af: gnunet_vpn::AfProfile::native().ipv4,
        destination,
        request_id,
    }
    .encode(&mut request)?;
    control.write_all(&request[..size])?;
    let response = gnunet_vpn::Response::decode(&read_frame(&mut control)?)?;
    if response.request_id != request_id {
        return Err("VPN lost the original redirect request".into());
    }
    let lease = response
        .address
        .ok_or("VPN did not allocate a redirect address")?;
    let mut packet = [0; 128];
    let size = gnunet_vpn::packet::build(
        Address::V4([198, 51, 100, 7]),
        lease,
        gnunet_vpn::packet::UDP,
        &[0x1f, 0x90, 0x01, 0xbb, 0, 0, 0, 0, 42],
        &mut packet,
    )?;
    // SAFETY: the caller retains the original provider and this packet remains live.
    check(unsafe { gnunet_vpn_receive(vpn, packet.as_ptr(), size) })?;
    let observed = read_frame(&mut monitor)?;
    let observed = dht::MonitorGet::decode(&observed)?;
    if observed.block_type != 22 || observed.key != &first_key {
        return Err("VPN ingress did not issue the original REGEX state lookup".into());
    }

    let string = StringBytes::new(term)?;
    let mut announcement = service_stream(ipc, "regex")?;
    let mut search = service_stream(ipc, "regex")?;
    let size = Request::Announce {
        compression: 8,
        reserved: 0,
        refresh_delay: RelativeTime::from_micros(60_000_000),
        regex: string,
    }
    .encode(&mut request)?;
    announcement.write_all(&request[..size])?;
    let size = Request::Search { string }.encode(&mut request)?;
    search.write_all(&request[..size])?;
    if SearchResult::decode(&read_frame(&mut search)?)?.peer != expected_peer {
        return Err("local DHT returned a result without the worker's PILS identity".into());
    }
    Ok(())
}

fn service_stream(ipc: &Path, service: &str) -> io::Result<UnixStream> {
    let stream = UnixStream::connect(ipc.join(service))?;
    let budget = Some(Duration::from_secs(4));
    stream.set_read_timeout(budget)?;
    stream.set_write_timeout(budget)?;
    Ok(stream)
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let size = usize::from(u16::from_be_bytes([header[0], header[1]]));
    let mut result = vec![0; size];
    result
        .get_mut(..4)
        .ok_or("truncated REGEX result")?
        .copy_from_slice(&header);
    stream.read_exact(&mut result[4..])?;
    Ok(result)
}
