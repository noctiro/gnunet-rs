//! Actual unwritten removal and refusal after a positive native write.
#![cfg(any(unix, windows))]
use gnunet_cadet_host::{ChannelSlot, Client, EndpointSource, Instance, Limits, PortSlot, Step};
use gnunet_service_runtime::local::{Listener, Stream};
use gnunet_wire::official::cadet::{Request, Response};
use std::{
    error::Error,
    io,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};
type Failure = Box<dyn Error>;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = std::fs::remove_dir_all(&self.0);
    }
}
async fn read_exact(stream: &Stream, bytes: &mut [u8]) -> io::Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        stream.readable().await?;
        match stream.try_read(&mut bytes[offset..]) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => offset += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
#[test]
fn discard_proves_no_write_and_restores_only_the_original_credit() -> Result<(), Failure> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), exercise_discard()).await? })
}
async fn exercise_discard() -> Result<(), Failure> {
    let directory = Directory(std::env::temp_dir().join(format!(
        "cadet-discard-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory.0)?;
    }
    #[cfg(windows)]
    std::fs::create_dir(&directory.0)?;
    let path = directory.0.join("c");
    let listener = Listener::bind(&path)?;
    let mut domain = Instance::new();
    let mut ports = [PortSlot::new()];
    let mut channels = [ChannelSlot::new(); 2];
    let mut client = Client::new(
        &mut domain,
        EndpointSource::unix(path),
        &mut ports,
        &mut channels,
        Limits {
            io_slice_bytes: 1,
            ..Limits::default()
        },
    )?;
    let Step::Connected(epoch) = client.drive(None).await? else {
        return Err("MQ not attached".into());
    };
    let (peer, _) = listener.accept().await?;
    let original = client.open([7; 32], [9; 64])?;
    let transmit = client.pending_transmit().ok_or("original CREATE absent")?;
    assert!(client.discard_unexposed(transmit)?);
    assert!(client.channel_info(original).is_err());
    assert_eq!(client.pending_transmit(), None);
    assert_eq!(client.epoch(), Some(epoch));
    assert!(
        matches!(peer.try_read(&mut [0]),Err(error) if error.kind()==io::ErrorKind::WouldBlock)
    );
    let channel = client.open([7; 32], [9; 64])?;
    let transmit = client
        .pending_transmit()
        .ok_or("replacement CREATE absent")?;
    assert!(matches!(
        client.drive(None).await?,
        Step::Activity {
            written_bytes: 1,
            ..
        }
    ));
    let mut create = [0; 108];
    read_exact(&peer, &mut create[..1]).await?;
    assert!(!client.discard_unexposed(transmit)?);
    assert_eq!(client.pending_transmit(), Some(transmit));
    loop {
        match client.drive(None).await? {
            Step::Written(written) if written.transmit == transmit => break,
            Step::Activity { .. } => {}
            _ => return Err("original prefix did not drain".into()),
        }
    }
    read_exact(&peer, &mut create[1..]).await?;
    let Request::ChannelCreate {
        channel: wire,
        peer: remote,
        port,
        ..
    } = Request::decode(&create)?
    else {
        return Err("wrong original frame".into());
    };
    assert_eq!(remote, [7; 32]);
    assert_eq!(port, [9; 64]);
    let mut ack = [0; 8];
    Response::Ack { channel: wire }.encode(&mut ack)?;
    let mut offset = 0;
    while offset < ack.len() {
        peer.writable().await?;
        match peer.try_write(&ack[offset..]) {
            Ok(0) => return Err("zero native write".into()),
            Ok(n) => offset += n,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error.into()),
        }
    }
    loop {
        match client.drive(None).await? {
            Step::Credit {
                channel: current,
                available: 1,
            } if current == channel => break,
            Step::Activity { .. } => {}
            _ => return Err("original service credit absent".into()),
        }
    }
    let transmit = client.send(channel, 0, &[0, 4, 0, 0])?;
    assert_eq!(client.channel_info(channel)?.send_credit, 0);
    assert!(client.discard_unexposed(transmit)?);
    assert_eq!(client.channel_info(channel)?.send_credit, 1);
    assert!(client.discard_unexposed(transmit).is_err());
    assert_eq!(client.channel_info(channel)?.send_credit, 1);
    assert_eq!(client.epoch(), Some(epoch));
    assert!(
        matches!(peer.try_read(&mut [0]),Err(error) if error.kind()==io::ErrorKind::WouldBlock)
    );
    client.close()?;
    Ok(())
}
