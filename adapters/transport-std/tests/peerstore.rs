//! Real Unix MQ, durable reopen, writer exclusion and iterator snapshot checks.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions test actual durability and original IPC outcomes"
)]
use gnunet_crypto::EddsaPublicKey;
use gnunet_service_runtime::connection::Connection;
use gnunet_tcp_communicator_core::{services, session::ReplayKind};
use gnunet_transport_host::peerstore::{Journal, Server};
use gnunet_types::Error;
use std::{
    future::poll_fn,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixStream,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, std::io::Error> {
        let p = std::env::temp_dir().join(format!(
            "gnunet-rust-ps-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&p)?;
        Ok(Self(p))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
async fn receive(stream: &mut UnixStream) -> Result<Vec<u8>, std::io::Error> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await?;
    let size = usize::from(u16::from_be_bytes([header[0], header[1]]));
    if size < 4 {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&header);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
#[tokio::test(flavor = "current_thread")]
async fn owned_backend_snapshots_and_commits_before_ack_and_never_rewinds()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = Directory::new()?;
    let path = directory.0.join("history");
    let mut journal = Journal::open(&path)?;
    assert!(matches!(Journal::open(&path), Err(Error::Conflict)));
    let (_, reserved) = journal.reserve_monotime(9000, 1000)?;
    let mut server = Server::new(2)?;
    let (server_stream, mut client) = UnixStream::pair()?;
    server.admit(Connection::from_unix(server_stream))?;
    let peer = EddsaPublicKey::from_bytes([6; 32]);
    let kind = ReplayKind::Handshake;
    let work = async {
        let mut out = [0; 256];
        let n = services::replay_store(1, peer, kind, 1000u64.to_be_bytes(), &mut out)?;
        client.write_all(&out[..n]).await?;
        assert_eq!(
            services::Peerstore::decode(&receive(&mut client).await?)?,
            services::Peerstore::Stored(1, 1)
        );
        let n = services::replay_start(2, peer, kind, &mut out)?;
        client.write_all(&out[..n]).await?;
        match services::Peerstore::decode(&receive(&mut client).await?)? {
            services::Peerstore::Record(2, actual, _, _, value) => {
                assert_eq!(actual, peer);
                assert_eq!(value, 1000u64.to_be_bytes());
            }
            _ => return Err(Box::<dyn std::error::Error>::from(Error::Malformed)),
        }
        // Replace while the iterator remains live. The original snapshot must end;
        // seeing the replacement would recreate the production self-feeding loop.
        let n = services::replay_store(3, peer, kind, 2000u64.to_be_bytes(), &mut out)?;
        client.write_all(&out[..n]).await?;
        assert_eq!(
            services::Peerstore::decode(&receive(&mut client).await?)?,
            services::Peerstore::Stored(3, 1)
        );
        let n = services::replay_next(2, &mut out)?;
        client.write_all(&out[..n]).await?;
        assert_eq!(
            services::Peerstore::decode(&receive(&mut client).await?)?,
            services::Peerstore::End(2, 1)
        );
        let n = services::replay_store(4, peer, kind, 1000u64.to_be_bytes(), &mut out)?;
        client.write_all(&out[..n]).await?;
        assert_eq!(
            services::Peerstore::decode(&receive(&mut client).await?)?,
            services::Peerstore::Stored(4, -1)
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(3),async{
  tokio::select!{result=work=>result,result=async{loop{poll_fn(|cx|server.poll_step(cx,&mut journal,1)).await?;}}=>result}
 }).await??;
    server.shutdown();
    drop(server);
    drop(journal);
    let mut journal = Journal::open(&path)?;
    let (first, _) = journal.reserve_monotime(1, 1)?;
    assert!(first > reserved);
    let mut server = Server::new(1)?;
    let (server_stream, mut client) = UnixStream::pair()?;
    server.admit(Connection::from_unix(server_stream))?;
    let work = async {
        let mut out = [0; 256];
        let n = services::replay_start(5, peer, kind, &mut out)?;
        client.write_all(&out[..n]).await?;
        match services::Peerstore::decode(&receive(&mut client).await?)? {
            services::Peerstore::Record(5, _, _, _, value) => {
                assert_eq!(value, 2000u64.to_be_bytes())
            }
            _ => return Err(Box::<dyn std::error::Error>::from(Error::Malformed)),
        }
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    tokio::time::timeout(std::time::Duration::from_secs(3),async{tokio::select!{result=work=>result,result=async{loop{poll_fn(|cx|server.poll_step(cx,&mut journal,1)).await?;}}=>result}}).await??;
    server.shutdown();
    Ok(())
}

#[test]
fn accepted_filename_extensions_never_replace_the_directory_writer_fence()
-> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::fs::MetadataExt;
    for name in ["ledger.new", "ledger.lock"] {
        let directory = Directory::new()?;
        let path = directory.0.join(name);
        let mut journal = Journal::open(&path)?;
        let fence = directory.0.join(".gnunet-peerstore-owner.lock");
        let before = std::fs::metadata(&fence)?;
        let (_, last) = journal.reserve_monotime(10, 100)?;
        let after = std::fs::metadata(&fence)?;
        assert_eq!((before.dev(), before.ino()), (after.dev(), after.ino()));
        assert!(matches!(
            Journal::open(directory.0.join("sibling")),
            Err(Error::Conflict)
        ));
        assert!(matches!(Journal::open(&fence), Err(Error::InvalidInput)));
        assert!(matches!(
            Journal::open(directory.0.join(".GNUNET-PEERSTORE-OWNER.LOCK")),
            Err(Error::InvalidInput)
        ));
        drop(journal);
        let mut journal = Journal::open(&path)?;
        let (first, end) = journal.reserve_monotime(1, 1)?;
        assert!(first > last);
        // Snapshot layout belongs to the codec tests. A real second reopen
        // must accept the entire committed file and retain its actual highwater.
        drop(journal);
        let journal = Journal::open(&path)?;
        assert_eq!(journal.highwater(), end);
        let mut files: Vec<_> = std::fs::read_dir(&directory.0)?
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .map(|entry| entry.file_name())
            .collect();
        files.sort();
        assert_eq!(files.len(), 2); // committed data and stable owner fence only
    }
    Ok(())
}
