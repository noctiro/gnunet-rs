//! Pure coordinator regression with actual Book provenance and durable monotime.
//! No CORE/PILS daemon, peer transport or official C execution is represented.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assert actual signed-route intent and complete endpoint path through the native coordinator"
)]
use super::*;
use gnunet_cadet::{
    service as app,
    tunnel::{SkippedSlot, Storage, identity_dh},
};
use gnunet_service_runtime::{
    clock::SystemClock, credentials::UnixAccess, service::ServiceOptions,
};
use gnunet_wire::official::cadet_peer::CONNECTION_INITIATOR_PURPOSE;
use std::{path::PathBuf, sync::Arc};

struct Draw(u8);
impl Entropy for Draw {
    fn fill(&mut self, bytes: &mut [u8]) -> Result<(), ProtocolError> {
        bytes.fill(self.0);
        self.0 = self.0.checked_add(1).ok_or(ProtocolError::Entropy)?;
        Ok(())
    }
}
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _removed = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn betty_signed_reset_uses_existing_reverse_path_without_replacing_original_route()
-> Result<(), Box<dyn std::error::Error>> {
    for route_count in [1, 4] {
        let one = gnunet_crypto::EddsaPrivateKey::from_seed([1; 32]);
        let two = gnunet_crypto::EddsaPrivateKey::from_seed([2; 32]);
        let (local_key, remote) = if one.public_key().as_bytes() > two.public_key().as_bytes() {
            (one, *two.public_key().as_bytes())
        } else {
            (two, *one.public_key().as_bytes())
        };
        let local = *local_key.public_key().as_bytes();
        let relay = [9; 32];
        let name = format!(
            "gnrs-cadet-reset-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        );
        let directory = Directory(std::env::temp_dir().join(name));
        gnunet_native::filesystem::Directory::open(&std::env::temp_dir())?
            .create_private_directory(
                directory.0.file_name().ok_or(ProtocolError::InvalidInput)?,
            )?;
        let mut store = crate::signing::monotime::Store::open(directory.0.join("monotime"), local)?;
        let mut service_instance = app::Instance::new();
        let mut clients = [app::ClientSlot::new(); 1];
        let mut ports = [app::PortSlot::new(); 1];
        let mut channels = [app::ChannelSlot::new(); 1];
        let mut bytes = [[0; 16]; 2];
        let mut messages = bytes.each_mut().map(|bytes| app::MessageSlot::new(bytes));
        let service = app::Service::new(
            &mut service_instance,
            local,
            &mut clients,
            &mut ports,
            &mut channels,
            &mut messages,
            app::Limits {
                window: 1,
                loop_payload_bytes: 16,
                remote_payload_bytes: 16,
            },
        )?;
        let mut server = server::Server::new(
            service,
            server::Limits {
                clients: 1,
                io_slice_bytes: 64,
            },
            ServiceOptions::default(),
            UnixAccess::default(),
            Arc::new(SystemClock),
        )?;
        let context_domain = context::Instance::new();
        let mut contexts = [const { context::Slot::new() }; 1];
        let contexts = context::Registry::new(&context_domain, &mut contexts)?;
        let channel_domain = peer::Instance::new();
        let source_domain = identity_dh::Instance::new();
        let mut source_slots = [const { identity_dh::Slot::new() }; 1];
        let mut sources = identity_dh::Registry::new(&source_domain, &mut source_slots)?;
        let source_binding = sources.bind(local, 1)?;
        let mut skipped1 = [const { SkippedSlot::new() }; 1];
        let mut staging1 = [const { SkippedSlot::new() }; 1];
        let mut skipped2 = [const { SkippedSlot::new() }; 1];
        let mut staging2 = [const { SkippedSlot::new() }; 1];
        let mut plaintext = [0; 256];
        let mut ciphertext = [0; 1024];
        let storage = super::super::Storage {
            contexts,
            channel_domain: &channel_domain,
            tunnels: vec![controller::Stores {
                first: Storage {
                    skipped: &mut skipped1,
                    staging: &mut staging1,
                },
                second: Storage {
                    skipped: &mut skipped2,
                    staging: &mut staging2,
                },
            }],
            channels: vec![],
            plaintext: &mut plaintext,
            ciphertext: &mut ciphertext,
        };
        let mut state = State::new(
            &mut server,
            storage,
            source_binding.source(),
            Limits {
                tunnel: controller::Limits {
                    crypto: gnunet_cadet::tunnel::Limits {
                        plaintext_bytes: 256,
                        maximum_gap: 1,
                    },
                    ..controller::Limits::default()
                },
                ..Limits::default()
            },
            Draw(5),
            MonoInstant(0),
        )?;
        let mut book_instance = connection::Instance::new();
        let mut neighbors = [connection::NeighborSlot::new(); 1];
        let mut routes = [connection::RouteSlot::<4>::new(); 4];
        let mut origins = [connection::OriginSlot::new(); 1];
        let mut frame_bytes = [[0; 512]; 8];
        let mut frames = frame_bytes
            .each_mut()
            .map(|bytes| connection::FrameSlot::new(bytes));
        let mut book = Book::new(
            &mut book_instance,
            local,
            &mut neighbors,
            &mut routes[..route_count],
            &mut origins,
            &mut frames,
            MonoInstant(0),
            connection::Limits::default(),
        )?;
        let neighbor = book.neighbor_up(relay)?;
        book.neighbor_ready(neighbor, true)?;
        let incoming_path = [remote, relay, local];
        let connection::Event::Created {
            route: original, ..
        } = book.receive(
            neighbor,
            PeerMessage::ConnectionCreate {
                options_bytes: [2, 0, 0, 0],
                has_monotime_bytes: [0; 4],
                monotime: 0,
                monotime_signature: [0; 64],
                connection: [3; 32],
                path: PathPeers::new(&incoming_path),
            },
            MonoInstant(0),
        )?
        else {
            return Err(ProtocolError::Malformed.into());
        };
        let ack = book.next_frame().ok_or(ProtocolError::NotReady)?.frame;
        let attempt = book.start(ack)?;
        book.exposed(attempt)?;
        book.settle(attempt, true, MonoInstant(0))?;
        book.release_frame(ack)?;
        book.neighbor_ready(neighbor, true)?;
        assert_eq!(book.select(remote), Some(original));
        let index = state.ensure_tunnel(remote, &book, MonoInstant(0))?;
        state.drive_initial(index, MonoInstant(0))?;
        assert!(state.tunnels[index].reset.pending());
        assert!(!state.ensure_route(index, &mut book, MonoInstant(0))?);
        assert_eq!(state.monotime_needed, route_count > 1);
        assert!(state.signs.iter().all(Option::is_none));
        state.monotime = Some(store.reserve(77, 2)?);
        assert!(!state.ensure_route(index, &mut book, MonoInstant(1))?);
        if route_count == 1 {
            assert!(state.signs.iter().all(Option::is_none));
            assert_eq!(
                state
                    .monotime
                    .as_ref()
                    .ok_or(ProtocolError::NotReady)?
                    .remaining(),
                2
            );
            assert!(state.tunnels[index].reset.pending());
            continue;
        }
        let task = *state
            .signs
            .iter()
            .flatten()
            .next()
            .ok_or(ProtocolError::NotReady)?;
        assert_ne!(task.request.route(), original);
        assert_eq!(
            book.route_peers(task.request.route())?,
            &[local, relay, remote]
        );
        let mut purpose = [0; 16];
        task.request.purpose(&mut purpose)?;
        let signature = local_key.sign(CONNECTION_INITIATOR_PURPOSE, &purpose)?;
        book.signed(task.request, local, *signature.as_bytes(), MonoInstant(1))?;
        for now in 2..5 {
            state.drive_initial(index, MonoInstant(now))?;
            assert!(!state.ensure_route(index, &mut book, MonoInstant(now))?);
        }
        assert_eq!(state.signs.iter().flatten().count(), 1);
        assert_eq!(
            state
                .monotime
                .as_ref()
                .ok_or(ProtocolError::NotReady)?
                .remaining(),
            1
        );
        assert_eq!(book.route_info(original)?.phase, connection::Phase::Ready);
        assert_eq!(book.route_peers(original)?, incoming_path);
        assert!(
            state.tunnels[index]
                .owner
                .as_ref()
                .ok_or(ProtocolError::NotReady)?
                .snapshot()
                .confirmed
                .is_none()
        );
    }
    Ok(())
}
