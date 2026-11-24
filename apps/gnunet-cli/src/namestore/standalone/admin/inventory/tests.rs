use super::*;
use gnunet::wire::identity::{Request, Response};
use std::{
    error::Error,
    fs,
    path::PathBuf,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
    sync::mpsc,
};

struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _removed = fs::remove_dir_all(&self.0);
    }
}

const KEY: [u8; 36] = [
    0, 1, 0, 20, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
    3, 3, 3, 3, 3,
];

async fn observe_name(
    names: &mut Names<'_, '_>,
    control: &mut Control,
    expected: Option<&[u8]>,
) -> Result<()> {
    let key = SecretKeyView::new(&KEY)?;
    let hard = Some(control.hard());
    poll_fn(|cx| {
        control.check(cx)?;
        let observed = names.poll(cx, hard)?;
        let mut matched = expected.is_none();
        names.with_name(key, |name| {
            matched = expected == Some(name);
            Ok(())
        })?;
        if matched {
            Poll::Ready(Ok(()))
        } else {
            if observed == Observation::Activity {
                cx.waker().wake_by_ref();
            }
            Poll::Pending
        }
    })
    .await
}

#[test]
fn live_inventory_uses_original_add_rename_and_delete_after_end() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let scratch = std::env::temp_dir().join(format!(
            "gnrs-inv-{}-{}",
            std::process::id(),
            SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
        ));
        fs::create_dir(&scratch)?;
        let scratch = Scratch(scratch);
        let socket = scratch.0.join("id");
        let listener = UnixListener::bind(&socket)?;
        let (change, mut changes) = mpsc::unbounded_channel::<Option<&'static [u8]>>();
        let source = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut buffer = [0; 1024];
            stream.read_exact(&mut buffer[..4]).await?;
            if !matches!(Request::decode(&buffer[..4])?, Request::Start) {
                return Err("expected IDENTITY START on the original stream".into());
            }
            let size = Response::EndOfList.encode(&mut buffer)?;
            stream.write_all(&buffer[..size]).await?;
            let key = SecretKeyView::new(&KEY)?;
            while let Some(name) = changes.recv().await {
                let size = Response::Update { name, key }.encode(&mut buffer)?;
                stream.write_all(&buffer[..size]).await?;
            }
            if stream.read(&mut buffer).await? != 0 {
                return Err("the original stream remained active after close".into());
            }
            Ok::<(), Box<dyn Error + Send + Sync>>(())
        });
        let instance = identity::Instance::new();
        let mut control = Control::new(Duration::from_secs(5), "NAMESTORE live identity test")?;
        let mut inventory =
            Inventory::open(&instance, EndpointSource::unix(socket), &mut control).await?;
        let mut names = Names::Live(&mut inventory);
        for name in [
            Some(b"initial".as_slice()),
            Some(b"renamed".as_slice()),
            None,
        ] {
            change.send(name)?;
            observe_name(&mut names, &mut control, name).await?;
        }
        names.close();
        drop(change);
        source.await?.map_err(|error| error as Box<dyn Error>)?;
        Ok(())
    })
}
