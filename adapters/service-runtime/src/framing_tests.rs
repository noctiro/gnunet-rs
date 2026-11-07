//! Actual original-socket, token, storage and resource-boundary regressions.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Physical ownership assertions accompany fallible local setup"
)]
use super::*;
use std::future::poll_fn;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
fn runtime() -> io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}
fn limits(accounting: Accounting, slice: usize, bytes: usize, frames: usize) -> Limits {
    Limits {
        frame_bytes: 65535,
        ordinary: Budget { frames, bytes },
        reserved: Budget::default(),
        accounting,
        io_slice_bytes: slice,
    }
}
async fn pair() -> io::Result<(Connection, tokio::net::TcpStream)> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let (client, server) = tokio::join!(
        tokio::net::TcpStream::connect(listener.local_addr()?),
        listener.accept(),
    );
    let client = client?;
    let (server, _) = server?;
    client.set_nodelay(true)?;
    server.set_nodelay(true)?;
    Ok((Connection::from_tcp(server), client))
}
fn frame(value: u8) -> Vec<u8> {
    vec![0, 8, 0, 99, value, value, value, value]
}
async fn rx<Origin: Copy>(io: &mut Framed<Origin>) -> io::Result<()> {
    loop {
        match poll_fn(|cx| io.poll_read(cx)).await? {
            ReadStep::Progress { complete: true, .. } => return Ok(()),
            ReadStep::Progress { .. } => {}
            ReadStep::Eof => return Err(io::ErrorKind::UnexpectedEof.into()),
        }
    }
}
#[derive(Debug)]
struct Brand(u8);
#[derive(Clone, Copy, Debug)]
struct Origin<'a> {
    brand: &'a Brand,
    id: u8,
}
impl PartialEq for Origin<'_> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.brand, other.brand) && self.id == other.id
    }
}
impl Eq for Origin<'_> {}
#[test]
fn actual_positive_writes_keep_foreign_brand_distinct_and_remove_only_unstarted_originals()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let a = Brand(1);
        let b = Brand(1);
        assert_eq!(a.0, b.0);
        let first = Origin { brand: &a, id: 1 };
        let removed = Origin { brand: &a, id: 2 };
        let next = Origin { brand: &b, id: 1 };
        assert_ne!(first, next);
        let (connection, mut peer) = pair().await?;
        let mut io = Framed::new(connection, limits(Accounting::Retained, 1, 32, 4))?;
        let one = frame(11);
        let two = frame(22);
        io.enqueue_owned(OwnedFrame::new(one.clone()), first, Class::Ordinary)
            .map_err(|r| r.reason)?;
        io.enqueue_copy(&frame(33), removed, Class::Ordinary)?;
        let progress = poll_fn(|cx| io.poll_write(cx)).await?;
        assert_eq!(
            progress,
            WriteProgress {
                origin: first,
                bytes: 1,
                complete: false
            }
        );
        let mut prefix = [0; 1];
        peer.read_exact(&mut prefix).await?;
        let mut cancelled = Vec::new();
        assert_eq!(
            io.remove_unwritten(|_, _| true, |origin, n| cancelled.push((origin, n))),
            1
        );
        assert_eq!(cancelled, vec![(removed, 8)]);
        io.enqueue_owned(OwnedFrame::new(two.clone()), next, Class::Ordinary)
            .map_err(|r| r.reason)?;
        let mut counts = [1usize, 0];
        let mut completions = [0usize, 0];
        for _ in 0..15 {
            let p = poll_fn(|cx| io.poll_write(cx)).await?;
            let index = if p.origin == first {
                0
            } else {
                assert_eq!(p.origin, next);
                1
            };
            counts[index] += p.bytes;
            if p.complete {
                completions[index] += 1;
            }
        }
        assert_eq!(counts, [8, 8]);
        assert_eq!(completions, [1, 1]);
        assert_eq!(io.remaining_bytes(), 0);
        let mut tail = [0; 15];
        peer.read_exact(&mut tail).await?;
        let mut actual = prefix.to_vec();
        actual.extend(tail);
        let mut expected = one;
        expected.extend(two);
        assert_eq!(actual, expected);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(5),
                poll_fn(|cx| io.poll_write(cx))
            )
            .await
            .is_err()
        );
        Ok(())
    })
}
#[test]
fn exact_wire_accounting_and_extra_budget_never_replace_original_admission()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        for mode in [Accounting::Retained, Accounting::Remaining] {
            let (connection, mut peer) = pair().await?;
            let mut io = Framed::new(connection, limits(mode, 1, 8, 4))?;
            io.enqueue_copy(&frame(7), 1u8, Class::Ordinary)?;
            for _ in 0..4 {
                let p = poll_fn(|cx| io.poll_write(cx)).await?;
                assert_eq!(p.bytes, 1);
                assert!(!p.complete);
            }
            let mut prefix = [0; 4];
            peer.read_exact(&mut prefix).await?;
            assert_eq!(io.remaining_bytes(), 4);
            assert_eq!(
                io.capacity(4, Class::Ordinary),
                mode == Accounting::Remaining
            );
            if mode == Accounting::Remaining {
                io.enqueue_copy(&[0, 4, 0, 100], 2, Class::Ordinary)?;
            } else {
                assert_eq!(
                    io.enqueue_copy(&[0, 4, 0, 100], 2, Class::Ordinary),
                    Err(Error::WouldBlock)
                );
            }
        }
        let (connection, _peer) = pair().await?;
        let mut io = Framed::new(connection, limits(Accounting::Retained, 8, 8, 1))?;
        io.enqueue_copy(&frame(1), 1u8, Class::Ordinary)?;
        io.set_reserved(Budget {
            frames: 1,
            bytes: 4,
        })?;
        assert!(!io.capacity(4, Class::Ordinary));
        assert!(io.capacity(4, Class::Reserved));
        io.enqueue_copy(&[0, 4, 0, 100], 2, Class::Reserved)?;
        assert_eq!(io.set_reserved(Budget::default()), Err(Error::WouldBlock));
        assert_eq!(io.queued_frames(), 2);
        assert_eq!(io.charged_bytes(), 12);
        Ok(())
    })
}
#[test]
fn actual_partial_rx_wait_ready_borrow_and_mutable_secret_erasure_preserve_the_next_frame()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let (connection, mut peer) = pair().await?;
        let mut io = Framed::<()>::new(connection, limits(Accounting::Retained, 1, 32, 4))?;
        let first = frame(0x71);
        let next = frame(0x39);
        peer.write_all(&first[..3]).await?;
        for _ in 0..3 {
            assert!(matches!(
                poll_fn(|cx| io.poll_read(cx)).await?,
                ReadStep::Progress {
                    bytes: 1,
                    complete: false
                }
            ));
        }
        assert!(!io.release_frame());
        assert_eq!(io.rx.used, 3);
        assert_eq!(&io.rx.input[..3], &first[..3]);
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(5),
                poll_fn(|cx| io.poll_read(cx))
            )
            .await
            .is_err()
        );
        peer.write_all(&first[3..]).await?;
        peer.write_all(&next).await?;
        rx(&mut io).await?;
        assert_eq!(io.frame(), Some(first.as_slice()));
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(5),
                poll_fn(|cx| io.poll_read(cx))
            )
            .await
            .is_err()
        );
        assert_eq!(io.frame(), Some(first.as_slice()));
        io.frame_mut().ok_or(Error::NotReady)?[4..].zeroize();
        assert!(io.release_frame());
        assert!(io.rx.input.iter().all(|b| *b == 0));
        rx(&mut io).await?;
        assert_eq!(io.frame(), Some(next.as_slice()));
        assert!(io.release_frame());
        assert!(io.rx.input.iter().all(|b| *b == 0));
        Ok(())
    })
}
#[test]
fn retirement_closes_original_partial_mq_and_wipes_retained_incoming_secrets()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let (connection, mut peer) = pair().await?;
        let mut io = Framed::new(connection, limits(Accounting::Retained, 1, 32, 4))?;
        peer.write_all(&frame(0x61)).await?;
        rx(&mut io).await?;
        assert!(io.rx.input.contains(&0x61));
        io.enqueue_copy(&frame(0x53), 7u8, Class::Ordinary)?;
        let p = poll_fn(|cx| io.poll_write(cx)).await?;
        assert_eq!(p.bytes, 1);
        assert!(!p.complete);
        let mut first = [0; 1];
        peer.read_exact(&mut first).await?;
        io.retire();
        assert!(io.rx.input.iter().all(|b| *b == 0));
        assert!(io.frame().is_none());
        assert!(io.frame_mut().is_none());
        assert_eq!(io.queued_frames(), 0);
        assert_eq!(
            io.enqueue_copy(&frame(1), 8, Class::Ordinary),
            Err(Error::Closed)
        );
        let mut tail = Vec::new();
        peer.read_to_end(&mut tail).await?;
        assert!(tail.is_empty());
        assert_eq!(first, [0]);
        Ok(())
    })
}
#[test]
fn malformed_and_capacity_rejection_keep_original_identity_without_physical_io()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let (connection, peer) = pair().await?;
        let mut io = Framed::new(connection, limits(Accounting::Retained, 8, 16, 2))?;
        let bad = vec![0, 7, 0, 99, 1, 2, 3, 4];
        let rejected = match io.enqueue_owned(OwnedFrame::new(bad.clone()), 42u8, Class::Ordinary) {
            Err(r) => r,
            Ok(()) => return Err("invalid original admitted".into()),
        };
        assert_eq!(rejected.reason, Error::InvalidInput);
        assert_eq!(rejected.value.0.bytes(), bad);
        assert_eq!(rejected.value.1, 42);
        assert_eq!(io.remaining_bytes(), 0);
        assert_eq!(io.queued_frames(), 0);
        let mut byte = [0; 1];
        assert_eq!(
            peer.try_read(&mut byte).err().map(|e| e.kind()),
            Some(io::ErrorKind::WouldBlock)
        );
        io.enqueue_copy(&frame(1), 1, Class::Ordinary)?;
        io.enqueue_copy(&frame(2), 2, Class::Ordinary)?;
        assert_eq!(
            io.enqueue_copy(&frame(3), 3, Class::Ordinary),
            Err(Error::WouldBlock)
        );
        assert_eq!(io.remaining_bytes(), 16);
        Ok(())
    })
}
#[test]
fn real_clean_eof_and_partial_truncation_never_create_a_complete_frame()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let (connection, peer) = pair().await?;
        let mut clean = Framed::<()>::new(connection, limits(Accounting::Retained, 1, 16, 2))?;
        drop(peer);
        assert_eq!(poll_fn(|cx| clean.poll_read(cx)).await?, ReadStep::Eof);
        assert!(clean.frame().is_none());
        let (connection, mut peer) = pair().await?;
        let mut partial = Framed::<()>::new(connection, limits(Accounting::Retained, 1, 16, 2))?;
        peer.write_all(&[0, 8]).await?;
        drop(peer);
        for _ in 0..2 {
            assert!(matches!(
                poll_fn(|cx| partial.poll_read(cx)).await?,
                ReadStep::Progress {
                    complete: false,
                    ..
                }
            ));
        }
        assert_eq!(
            poll_fn(|cx| partial.poll_read(cx))
                .await
                .err()
                .map(|e| e.kind()),
            Some(io::ErrorKind::UnexpectedEof)
        );
        assert!(partial.frame().is_none());
        partial.retire();
        assert!(partial.rx.input.iter().all(|b| *b == 0));
        Ok(())
    })
}

#[test]
fn callback_unwind_cannot_leave_canceled_frames_or_phantom_queue_charge()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        let (connection, mut peer) = pair().await?;
        let mut io = Framed::new(connection, limits(Accounting::Retained, 8, 32, 4))?;
        for id in 1..=3 {
            io.enqueue_copy(&frame(id), id, Class::Ordinary)?;
        }
        let mut cancelled = Vec::new();
        let failure = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            io.remove_unwritten(
                |origin, _| origin < 3,
                |origin, _| {
                    cancelled.push(origin);
                    assert_ne!(origin, 2, "finite caller panic");
                },
            )
        }));
        assert!(failure.is_err());
        assert_eq!(cancelled, vec![1, 2]);
        assert_eq!(io.remaining_bytes(), 8);
        assert_eq!(io.charged_bytes(), 8);
        assert_eq!(io.queued_frames(), 1);
        let progress = poll_fn(|cx| io.poll_write(cx)).await?;
        assert_eq!(progress.origin, 3);
        assert!(progress.complete);
        let mut actual = [0; 8];
        peer.read_exact(&mut actual).await?;
        assert_eq!(actual.as_slice(), frame(3));
        Ok(())
    })
}

#[test]
fn untracked_vector_write_uses_one_real_progress_quantum_and_preserves_partial_tail()
-> Result<(), Box<dyn std::error::Error>> {
    runtime()?.block_on(async {
        for accounting in [Accounting::Remaining, Accounting::Retained] {
            let (connection, mut peer) = pair().await?;
            let mut io = Framed::new(connection, limits(accounting, 12, 32, 4))?;
            for value in [1, 2, 3] {
                io.enqueue_copy(&frame(value), (), Class::Ordinary)?;
            }
            let first = poll_fn(|cx| io.poll_write_untracked_batch(cx)).await?;
            assert_eq!(
                first,
                StreamWriteProgress {
                    bytes: 12,
                    completed_frames: 1
                }
            );
            assert_eq!(io.remaining_bytes(), 12);
            assert_eq!(
                io.charged_bytes(),
                if accounting == Accounting::Retained {
                    16
                } else {
                    12
                }
            );
            let mut removed = 0;
            assert_eq!(io.remove_unwritten(|(), _| true, |(), n| removed += n), 1);
            assert_eq!(removed, 8);
            io.enqueue_copy(&frame(4), (), Class::Ordinary)?;
            let second = poll_fn(|cx| io.poll_write_untracked_batch(cx)).await?;
            assert_eq!(
                second,
                StreamWriteProgress {
                    bytes: 12,
                    completed_frames: 2
                }
            );
            assert_eq!(io.remaining_bytes(), 0);
            assert_eq!(io.charged_bytes(), 0);
            let mut got = [0; 24];
            peer.read_exact(&mut got).await?;
            assert_eq!(got.as_slice(), [frame(1), frame(2), frame(4)].concat());
            // Untracked batching has no synthetic operation receipts to consume.
            assert_eq!(io.queued_frames(), 0);
        }
        Ok(())
    })
}
