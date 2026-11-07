//! Actual owned local listeners and checked core leases. Child fixture uses real
//! inherited fd0 and shared early capture; no host-side accept consumes backlog.
#![expect(
    clippy::expect_used,
    reason = "Finite owned-resource fixtures require each actual setup/outcome"
)]
#![expect(
    clippy::panic,
    reason = "Unexpected native effect is a failed finite state observation"
)]
use gnunet_arm_core::wire::ArmAbi;
use gnunet_arm_service_core::*;
use gnunet_arm_service_host::{
    addresses::Address,
    listeners::{BindOutcome, Error, Failure, ManagedListeners},
    registry::{Limits, Registry},
};
use gnunet_config::{BinaryPathCache, Configuration, Environment, ProjectData};
use gnunet_service_runtime::ActivatedSocket;
use socket2::SockRef;
use std::{
    io::{self, Read, Write},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream},
    os::{
        fd::AsRawFd,
        unix::{
            fs::PermissionsExt,
            net::{UnixListener, UnixStream},
            process::ExitStatusExt,
        },
    },
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "arm-host-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("owned directory");
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        match std::fs::remove_dir_all(&self.0) {
            Ok(()) | Err(_) => {}
        }
    }
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        match self.0.kill() {
            Ok(()) | Err(_) => {}
        }
        match self.0.wait() {
            Ok(_) | Err(_) => {}
        }
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build()
        .expect("local reactor")
}
static SPECS: [ServiceSpec<'static>; 2] = [
    ServiceSpec {
        name: b"one",
        binary: b"fixture",
        command: b"real-fixture",
        immediate: false,
        pipe_control: false,
    },
    ServiceSpec {
        name: b"two",
        binary: b"fixture",
        command: b"real-fixture",
        immediate: false,
        pipe_control: false,
    },
];
fn with_core(count: usize, test: impl FnOnce(&mut Owner<'_, '_, '_, '_>)) {
    let mut scope = OwnerScope::new();
    let mut services = [ServiceSlot::new(), ServiceSlot::new()];
    let mut listeners = (0..count).map(|_| ListenerSlot::new()).collect::<Vec<_>>();
    let mut clients = [];
    let mut frames = [];
    let mut owner = Owner::new(
        &mut scope,
        &SPECS,
        &mut services,
        &mut clients,
        &mut listeners,
        &mut frames,
        ArmAbi::U64Align8,
    )
    .expect("bounded owner");
    test(&mut owner);
}
fn apply_all<'scope>(host: &mut ManagedListeners<'scope>, owner: &mut Owner<'scope, '_, '_, '_>) {
    let mut count = 0;
    while host
        .apply_next(owner)
        .expect("checked actual listener effect")
    {
        count += 1;
        assert!(count <= 32);
    }
}
fn child(host: &ManagedListeners<'_>, index: usize) -> Process {
    let fd = host
        .descriptor(host.id(index).expect("attached original ID"))
        .expect("live original FD")
        .try_clone_to_owned()
        .expect("safe borrowed inheritance duplicate");
    Process(
        Command::new(env!("CARGO_BIN_EXE_gnunet-arm-listener-child-fixture"))
            .env("LISTEN_FDS", "1")
            .env("LISTEN_FDNAMES", "0")
            .stdin(Stdio::from(fd))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("actual fixture exec"),
    )
}
fn admitted<'scope>(owner: &mut Owner<'scope, '_, '_, '_>) -> ChildId<'scope> {
    let NativeEffect::Spawn { ticket, child, .. } = owner
        .take_native()
        .expect("native lease")
        .expect("requested real spawn")
    else {
        panic!("expected Spawn")
    };
    assert_eq!(
        owner
            .spawned(ticket, SpawnOutcome::Admitted, 10)
            .expect("actual fixture was admitted")
            .resource_closures,
        0
    );
    child
}
#[test]
fn queued_unix_connection_survives_readiness_cancel_disarm_and_actual_child_inheritance() {
    let directory = Directory::new();
    let path = directory.0.join("socket");
    with_core(1, |owner| {
        runtime().block_on(async {
            let mut host = ManagedListeners::new(1);
            assert!(matches!(
                host.bind_address(0, Address::Unix(path.clone()), 0o700)
                    .expect("bounded bind"),
                BindOutcome::Bound { .. }
            ));
            assert!(host.failures().is_empty());
            assert_eq!(
                std::fs::metadata(&path)
                    .expect("owned inode")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
            host.attach(owner).expect("attach actual FD");
            apply_all(&mut host, owner);
            assert_eq!(owner.startup_next(), Ok(false));
            let id = host.id(0).expect("ID");
            let raw = host.descriptor(id).expect("original").as_raw_fd();
            assert!(
                tokio::time::timeout(Duration::from_millis(5), host.next_event())
                    .await
                    .is_err()
            );
            assert_eq!(
                host.descriptor(id)
                    .expect("after canceled wait")
                    .as_raw_fd(),
                raw
            );
            let mut peer = UnixStream::connect(&path).expect("queued actual connection");
            peer.set_read_timeout(Some(Duration::from_secs(3)))
                .expect("bounded read");
            peer.write_all(b"queue").expect("queued bytes");
            let first = tokio::time::timeout(Duration::from_secs(2), host.next_event())
                .await
                .expect("actual backlog")
                .expect("readiness");
            assert_eq!(host.next_event().await.expect("retained event"), first);
            host.deliver(owner).expect("on demand");
            apply_all(&mut host, owner);
            let mut process = child(&host, 0);
            let child_id = admitted(owner);
            let mut reply = [0; 11];
            peer.read_exact(&mut reply)
                .expect("actual child accepted original queued connection");
            assert_eq!(&reply, b"child:queue");
            assert!(process.0.wait().expect("actual child reap").success());
            assert_eq!(
                owner
                    .reaped(child_id, Exit::Exited(0), 20)
                    .expect("actual reaped lifetime")
                    .resource_closures,
                0
            );
            apply_all(&mut host, owner);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), host.next_event())
                    .await
                    .is_err(),
                "cached readiness is cleared after child consumed backlog"
            );
            owner.begin_shutdown(30);
            apply_all(&mut host, owner);
            assert!(owner.listeners_closed());
            assert!(host.descriptor(id).is_none());
            assert!(!path.exists());
        })
    });
}
#[test]
fn actual_tcp_child_receives_queued_data_and_v6_is_v6only() {
    for endpoint in [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 0)),
    ] {
        with_core(1, |owner| {
            runtime().block_on(async {
                let mut host = ManagedListeners::new(1);
                assert!(matches!(
                    host.bind_address(0, Address::Tcp(endpoint), 0o777)
                        .expect("bounded TCP bind"),
                    BindOutcome::Bound { .. }
                ));
                assert!(
                    host.failures().is_empty(),
                    "this local profile requires real IPv4 and IPv6 support"
                );
                host.attach(owner).expect("attach");
                apply_all(&mut host, owner);
                assert_eq!(owner.startup_next(), Ok(false));
                let Address::Tcp(actual) = host.address(0).expect("actual endpoint") else {
                    panic!("TCP")
                };
                let mut peer = TcpStream::connect(actual).expect("queued local TCP");
                peer.set_read_timeout(Some(Duration::from_secs(3)))
                    .expect("bounded read");
                peer.write_all(b"queue").expect("queued data");
                let fd = host.descriptor(host.id(0).expect("ID")).expect("original");
                assert!(
                    SockRef::from(&fd)
                        .reuse_address()
                        .expect("actual REUSEADDR")
                );
                if actual.is_ipv6() {
                    assert!(SockRef::from(&fd).only_v6().expect("actual V6ONLY"));
                }
                tokio::time::timeout(Duration::from_secs(2), host.next_event())
                    .await
                    .expect("backlog")
                    .expect("ready");
                host.deliver(owner).expect("demand");
                apply_all(&mut host, owner);
                let mut process = child(&host, 0);
                let child_id = admitted(owner);
                let mut reply = [0; 11];
                peer.read_exact(&mut reply).expect("actual child accepted");
                assert_eq!(&reply, b"child:queue");
                assert!(process.0.wait().expect("actual reap").success());
                assert_eq!(
                    owner
                        .reaped(child_id, Exit::Exited(0), 20)
                        .expect("reaped")
                        .resource_closures,
                    0
                );
                owner.begin_shutdown(30);
                apply_all(&mut host, owner);
                assert!(owner.listeners_closed());
            })
        });
    }
}
#[test]
fn sibling_disarm_and_every_actual_close_precede_term_admission() {
    let directory = Directory::new();
    let path = directory.0.join("socket");
    with_core(2, |owner| {
        runtime().block_on(async {
            let mut host = ManagedListeners::new(2);
            assert!(matches!(
                host.bind_address(0, Address::Unix(path.clone()), 0o777)
                    .expect("Unix"),
                BindOutcome::Bound { .. }
            ));
            assert!(matches!(
                host.bind_address(0, Address::Tcp((Ipv4Addr::LOCALHOST, 0).into()), 0o777)
                    .expect("TCP"),
                BindOutcome::Bound { .. }
            ));
            assert!(host.failures().is_empty());
            host.attach(owner).expect("attach");
            apply_all(&mut host, owner);
            assert_eq!(owner.startup_next(), Ok(false));
            let peer = UnixStream::connect(&path).expect("actual demand");
            host.next_event().await.expect("ready");
            host.deliver(owner).expect("demand");
            assert!(owner.take_native().expect("not yet all disarmed").is_none());
            apply_all(&mut host, owner);
            // Native fixture exists independently; no process is fabricated from an effect.
            let mut process = Process(
                Command::new("/bin/sleep")
                    .arg("30")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("actual held child"),
            );
            let child_id = admitted(owner);
            owner.begin_shutdown(50);
            assert!(owner.take_native().expect("all close first").is_none());
            assert!(host.apply_next(owner).expect("first actual close"));
            assert!(!owner.listeners_closed());
            assert!(
                owner
                    .take_native()
                    .expect("second close still required")
                    .is_none()
            );
            assert!(host.apply_next(owner).expect("second actual close"));
            assert!(owner.listeners_closed());
            assert!(!path.exists());
            let NativeEffect::Term { ticket, child } = owner
                .take_native()
                .expect("cleanup lane")
                .expect("TERM only after every FD close")
            else {
                panic!("Term")
            };
            assert_eq!(child, child_id);
            assert!(
                Command::new("/bin/kill")
                    .arg("-TERM")
                    .arg(process.0.id().to_string())
                    .status()
                    .expect("TERM own exact child")
                    .success()
            );
            owner.term_attempted(ticket).expect("actual TERM attempted");
            let status = process.0.wait().expect("actual terminated child reap");
            assert!(!status.success());
            assert_eq!(status.signal(), Some(15));
            assert_eq!(
                owner
                    .reaped(child_id, Exit::Signaled(15), 60)
                    .expect("actual reap")
                    .resource_closures,
                0
            );
            assert!(owner.children_drained());
            drop(peer);
        })
    });
}
#[test]
fn adopted_parent_listener_and_replaced_owned_path_are_never_unlinked() {
    let directory = Directory::new();
    let path = directory.0.join("parent");
    let own = directory.0.join("own");
    runtime().block_on(async {
        let parent = UnixListener::bind(&path).expect("parent-owned inherited listener");
        let duplicate = parent.try_clone().expect("explicit parent offer");
        let mut host = ManagedListeners::new(2);
        host.adopt(0, ActivatedSocket::Unix(duplicate))
            .expect("owned offer");
        assert!(matches!(
            host.bind_address(0, Address::Unix(own.clone()), 0o777)
                .expect("own path"),
            BindOutcome::Bound { .. }
        ));
        assert!(host.failures().is_empty());
        std::fs::remove_file(&own).expect("owned replacement simulation");
        std::fs::write(&own, b"new owner").expect("replacement inode");
        drop(host);
        assert!(path.exists());
        assert_eq!(
            std::fs::read(&own).expect("replacement preserved"),
            b"new owner"
        );
        let _peer = UnixStream::connect(&path).expect("parent FD still live");
        drop(parent);
    });
}
#[test]
fn stale_socket_only_precheck_regular_and_live_entries_are_preserved() {
    // This fixture needs the last reference to its stale socket to be closed.
    // Sibling tests spawn children: a process descriptor snapshot can otherwise
    // keep that socket alive across this thread's drop. Create it only after
    // exec in a child running this one case, keeping every original assertion.
    const ISOLATED: &str = "GNUNET_ARM_STALE_LISTENER_ISOLATED";
    if std::env::var_os(ISOLATED).is_none() {
        let output = Command::new(std::env::current_exe().expect("same test binary"))
            .args([
                "--exact",
                "stale_socket_only_precheck_regular_and_live_entries_are_preserved",
                "--test-threads=1",
            ])
            .env(ISOLATED, "1")
            .output()
            .expect("isolated stale-path fixture");
        assert!(
            output.status.success()
                && String::from_utf8_lossy(&output.stdout)
                    .contains("test result: ok. 1 passed; 0 failed; 0 ignored;",),
            "isolated stale-path assertions failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let directory = Directory::new();
    let stale = directory.0.join("stale");
    let regular = directory.0.join("regular");
    let live = directory.0.join("live");
    drop(UnixListener::bind(&stale).expect("owned stale inode"));
    std::fs::write(&regular, b"keep").expect("owned regular");
    let live_listener = UnixListener::bind(&live).expect("owned live listener");
    runtime().block_on(async {
        let mut host = ManagedListeners::new(3);
        assert!(matches!(
            host.bind_address(0, Address::Unix(stale.clone()), 0o770)
                .expect("bounded"),
            BindOutcome::Bound { .. }
        ));
        assert!(matches!(
            host.bind_address(0, Address::Unix(regular.clone()), 0o777)
                .expect("nonfatal bind failure"),
            BindOutcome::Failed
        ));
        assert!(matches!(
            host.bind_address(0, Address::Unix(live.clone()), 0o777)
                .expect("nonfatal active failure"),
            BindOutcome::Failed
        ));
        assert_eq!(host.len(), 1);
        assert_eq!(
            host.failures()
                .iter()
                .filter(|f| matches!(f, Failure::Bind { .. }))
                .count(),
            2
        );
        assert_eq!(std::fs::read(&regular).expect("regular retained"), b"keep");
        assert_eq!(
            std::fs::metadata(&stale)
                .expect("rebound inode")
                .permissions()
                .mode()
                & 0o777,
            0o770
        );
        drop(host);
        assert!(!stale.exists());
        assert!(live.exists());
    });
    drop(live_listener);
}
struct Env;
impl Environment for Env {
    fn variable(&self, _: &[u8]) -> Option<Vec<u8>> {
        None
    }
    fn current_dir(&self) -> io::Result<PathBuf> {
        Ok(std::env::temp_dir())
    }
}
fn put(c: &mut Configuration, s: &[u8], k: &[u8], v: &[u8]) {
    c.set_value(s, k, Some(v)).expect("config");
}
#[test]
fn registry_cross_section_binding_and_permission_precedence_follow_source() {
    let directory = Directory::new();
    let path = directory.0.join("shared");
    let mut config = Configuration::default();
    for name in [b"first".as_slice(), b"second".as_slice()] {
        put(&mut config, name, b"BINARY", b"/owned/fixture");
        put(&mut config, name, b"START_ON_DEMAND", b"YES");
        put(&mut config, name, b"DISABLEV6", b"YES");
        put(
            &mut config,
            name,
            b"UNIXPATH",
            path.as_os_str().as_encoded_bytes(),
        );
    }
    put(&mut config, b"first", b"UNIX_MATCH_UID", b"YES");
    put(&mut config, b"second", b"UNIX_MATCH_GID", b"YES");
    let registry = Registry::from_config(
        &config,
        &Env,
        &ProjectData::default(),
        &mut BinaryPathCache::new(),
        Limits::default(),
    )
    .expect("registry");
    runtime().block_on(async {
        let mut host = ManagedListeners::new(4);
        host.bind_registry(&config, &registry, &Env, 4)
            .expect("complete collection");
        assert_eq!(host.len(), 1);
        assert!(
            host.failures()
                .iter()
                .any(|f| matches!(f, Failure::Bind { service: 0, .. })),
            "config newest section binds first; core registry is opposite DLL order"
        );
        assert_eq!(
            std::fs::metadata(&path)
                .expect("second owns actual listener")
                .permissions()
                .mode()
                & 0o777,
            0o770
        );
    });
    assert!(!path.exists());
}
#[test]
fn partial_attachment_capacity_retains_native_owners_until_explicit_drop() {
    let directory = Directory::new();
    let a = directory.0.join("a");
    let b = directory.0.join("b");
    with_core(1, |owner| {
        runtime().block_on(async {
            let mut host = ManagedListeners::new(2);
            assert!(matches!(
                host.bind_address(0, Address::Unix(a.clone()), 0o777)
                    .expect("a"),
                BindOutcome::Bound { .. }
            ));
            assert!(matches!(
                host.bind_address(1, Address::Unix(b.clone()), 0o777)
                    .expect("b"),
                BindOutcome::Bound { .. }
            ));
            assert!(host.failures().is_empty());
            assert!(matches!(
                host.attach(owner),
                Err(Error::Core(gnunet_arm_service_core::Error::Capacity))
            ));
            assert!(host.id(0).is_some());
            assert!(host.id(1).is_none());
            assert!(a.exists() && b.exists());
            assert!(host.descriptor(host.id(0).expect("retained ID")).is_some());
            owner.begin_shutdown(0);
            apply_all(&mut host, owner);
            assert!(!a.exists());
            assert!(b.exists());
            drop(host);
            assert!(!b.exists());
        })
    });
}

#[test]
fn foreign_owner_is_rejected_before_leasing_or_retiring_original_readiness() {
    let directory = Directory::new();
    let first = directory.0.join("first");
    let second = directory.0.join("second");
    let mut scope_a = OwnerScope::new();
    let mut scope_b = OwnerScope::new();
    let mut services_a = [ServiceSlot::new(), ServiceSlot::new()];
    let mut services_b = [ServiceSlot::new(), ServiceSlot::new()];
    let mut slots_a = [ListenerSlot::new()];
    let mut slots_b = [ListenerSlot::new()];
    let mut clients_a = [];
    let mut clients_b = [];
    let mut frames_a = [];
    let mut frames_b = [];
    let mut a = Owner::new(
        &mut scope_a,
        &SPECS,
        &mut services_a,
        &mut clients_a,
        &mut slots_a,
        &mut frames_a,
        ArmAbi::U64Align8,
    )
    .expect("owner a");
    let mut b = Owner::new(
        &mut scope_b,
        &SPECS,
        &mut services_b,
        &mut clients_b,
        &mut slots_b,
        &mut frames_b,
        ArmAbi::U64Align8,
    )
    .expect("owner b");
    runtime().block_on(async {
        let mut ha = ManagedListeners::new(1);
        let mut hb = ManagedListeners::new(1);
        assert!(matches!(
            ha.bind_address(0, Address::Unix(first.clone()), 0o700)
                .expect("bound a"),
            BindOutcome::Bound { .. }
        ));
        assert!(matches!(
            hb.bind_address(0, Address::Unix(second.clone()), 0o700)
                .expect("bound b"),
            BindOutcome::Bound { .. }
        ));
        ha.attach(&mut a).expect("attach a");
        hb.attach(&mut b).expect("attach b");
        assert!(matches!(
            ha.attach(&mut b),
            Err(Error::Core(gnunet_arm_service_core::Error::Stale))
        ));
        assert!(matches!(
            ha.apply_next(&mut b),
            Err(Error::Core(gnunet_arm_service_core::Error::Stale))
        ));
        assert!(
            hb.apply_next(&mut b)
                .expect("foreign attempt did not consume b's arm lease")
        );
        apply_all(&mut ha, &mut a);
        assert_eq!(a.startup_next(), Ok(false));
        assert_eq!(b.startup_next(), Ok(false));
        let peer = UnixStream::connect(&first).expect("queued a");
        let event = ha.next_event().await.expect("actual a readiness");
        assert!(matches!(
            ha.deliver(&mut b),
            Err(Error::Core(gnunet_arm_service_core::Error::Stale))
        ));
        assert_eq!(
            ha.next_event().await.expect("original event retained"),
            event
        );
        ha.deliver(&mut a).expect("right owner consumes own event");
        a.begin_shutdown(0);
        b.begin_shutdown(0);
        apply_all(&mut ha, &mut a);
        apply_all(&mut hb, &mut b);
        assert!(!first.exists() && !second.exists());
        drop(peer);
    });
}
