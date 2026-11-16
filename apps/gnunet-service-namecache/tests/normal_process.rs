//! Built service over native local IPC with literal official frames and real stop.
use gnunet_service_runtime::local::Stream;
use std::{
    error::Error,
    ffi::{OsStr, OsString},
    fs, io,
    path::PathBuf,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
#[path = "support/unix.rs"]
mod process;
#[cfg(windows)]
#[path = "support/windows.rs"]
mod process;
type Failure = Box<dyn Error>;
const BLOCK: &[u8] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/pkey_ascii-block.bin");
const QUERY: &[u8] =
    include_bytes!("../../../crates/gnunet-gnscrypto/tests/fixtures/pkey_ascii-query.bin");
fn check(value: bool, message: &'static str) -> io::Result<()> {
    if value {
        Ok(())
    } else {
        Err(io::Error::other(message))
    }
}
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        let mut nonce = [0; 16];
        gnunet_native::entropy::fill(&mut nonce[..12])?;
        let base = fs::canonicalize(std::env::temp_dir())?;
        let name = format!("nc-{:024x}", u128::from_le_bytes(nonce));
        gnunet_native::filesystem::Directory::open(&base)?
            .create_private_directory(OsStr::new(&name))?;
        Ok(Self(base.join(name)))
    }
    fn environment(&self) -> Vec<(OsString, OsString)> {
        let mut env = Vec::new();
        for key in [
            "SystemRoot",
            "WINDIR",
            "PATH",
            "PATHEXT",
            "TEMP",
            "TMP",
            "TMPDIR",
        ] {
            if let Some(value) = std::env::var_os(key) {
                env.push((key.into(), value));
            }
        }
        env.extend([
            ("HOME".into(), self.0.clone().into()),
            ("USERPROFILE".into(), self.0.clone().into()),
            ("GNUNET_BASE_CONFIG".into(), self.0.join("defaults").into()),
        ]);
        env
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}
fn packet(kind: u16, rid: u32, body: &[u8]) -> Result<Vec<u8>, Failure> {
    let size = u16::try_from(8 + body.len())?;
    let mut frame = size.to_be_bytes().to_vec();
    frame.extend_from_slice(&kind.to_be_bytes());
    frame.extend_from_slice(&rid.to_be_bytes());
    frame.extend_from_slice(body);
    Ok(frame)
}
async fn frame(stream: &mut Stream) -> Result<Vec<u8>, Failure> {
    let mut head = [0; 4];
    stream.read_exact(&mut head).await?;
    let size = usize::from(u16::from_be_bytes([head[0], head[1]]));
    check(size >= 4, "invalid service frame length")?;
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&head);
    stream.read_exact(&mut bytes[4..]).await?;
    Ok(bytes)
}
async fn connect(path: &std::path::Path) -> Result<Stream, Failure> {
    let until = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match Stream::connect(path).await {
            Ok(stream) => return Ok(stream),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ) && tokio::time::Instant::now() < until =>
            {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
}
async fn exchange(path: &std::path::Path) -> Result<(), Failure> {
    let mut stream = connect(path).await?;
    let mut body = vec![0; 8];
    body.extend_from_slice(BLOCK);
    stream.write_all(&packet(433, 1, &body)?).await?;
    check(
        frame(&mut stream).await? == packet(434, 1, &1_i32.to_be_bytes())?,
        "CACHE result changed",
    )?;
    stream.write_all(&packet(431, 2, QUERY)?).await?;
    let mut found = BLOCK[104..112].to_vec();
    found.extend_from_slice(BLOCK);
    check(
        frame(&mut stream).await? == packet(432, 2, &found)?,
        "LOOKUP changed ciphertext or expiration",
    )?;
    for (rid, result) in [(3, 1_i32), (4, 0_i32)] {
        stream.write_all(&packet(1850, rid, QUERY)?).await?;
        check(
            frame(&mut stream).await? == packet(1851, rid, &result.to_be_bytes())?,
            "DELETE result changed",
        )?;
    }
    stream.write_all(&packet(431, 5, QUERY)?).await?;
    check(
        frame(&mut stream).await? == packet(432, 5, &[0; 8])?,
        "deleted block remained visible",
    )?;
    stream.write_all(&[0, 8, 1, 175, 0, 0, 0, 9]).await?;
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::NotConnected
            ) => {}
        Err(error) => return Err(error.into()),
        Ok(_) => return Err("malformed request did not retire its source".into()),
    }
    drop(stream);
    let mut fresh = connect(path).await?;
    fresh.write_all(&packet(431, 6, QUERY)?).await?;
    check(
        frame(&mut fresh).await? == packet(432, 6, &[0; 8])?,
        "malformed peer stopped service or corrupted state",
    )?;
    Ok(())
}
#[test]
fn normal_local_cache_lookup_delete_and_parent_stop() -> Result<(), Failure> {
    let directory = Directory::new()?;
    fs::create_dir(directory.0.join("defaults"))?;
    let path = directory.0.join("ipc");
    let config = directory.0.join("namecache service.conf");
    let mut bytes = b"[namecache]\nUNIXPATH = ".to_vec();
    bytes.extend_from_slice(&gnunet_native::os_bytes::encode(path.as_os_str()));
    bytes.extend_from_slice(b"\n[statistics]\nDISABLE = YES\n");
    fs::write(&config, bytes)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut service = process::Service::new()?;
    let result = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(15), async {
            service.start(&directory, &config).await?;
            exchange(&path).await?;
            service.stop().await?;
            match fs::symlink_metadata(&path) {
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
                Ok(_) => return Err("owned socket pathname survived service exit".into()),
            }
            Ok::<(), Failure>(())
        })
        .await?
    });
    let cleanup = runtime.block_on(service.retire());
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => {
            Err(format!("{error}; independent child retirement: {cleanup}").into())
        }
    }
}
