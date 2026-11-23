use super::*;
use gnunet_wire::testing::Init;
use std::num::NonZeroU32;
use tokio::sync::oneshot;

const TOPOLOGY: &std::ffi::CStr = c"[DEFAULTS]\nSUBNETS = 0\nCARRIER_PEERS = 0\nSUBNET_PEERS = 0\nTESTBED_PLUGIN = testing\n[BACKBONE]\nCARRIERS = 0\nBACKBONE_PEERS = 1\n";

fn key() -> BarrierKey {
    super::super::Reaches::named(c"ready", NonZeroU32::MIN).key
}

async fn send(pipe: &mut (impl AsyncWrite + Unpin), message: ToHelper<'_>) -> io::Result<()> {
    let mut frame = vec![0; message.encoded_len()];
    let _length = message.encode(&mut frame).map_err(io::Error::other)?;
    pipe.write_all(&frame).await
}

async fn receive(pipe: &mut (impl AsyncRead + Unpin)) -> io::Result<FromHelper> {
    let mut frame = [0; BARRIER_FRAME_LEN];
    let _length = pipe.read_exact(&mut frame[..HEADER_LEN]).await?;
    let header = MessageHeader::decode(&frame[..HEADER_LEN]).map_err(io::Error::other)?;
    let remaining = frame
        .get_mut(HEADER_LEN..header.size())
        .ok_or_else(|| io::Error::other("oversized fixture frame"))?;
    let _length = pipe.read_exact(remaining).await?;
    FromHelper::decode(&frame[..header.size()]).map_err(io::Error::other)
}

#[tokio::test]
async fn program_runs_batch_and_releases_inherited_barrier()
-> Result<(), Box<dyn std::error::Error>> {
    let (controller, worker) = tokio::io::duplex(8);
    let (worker_in, worker_out) = tokio::io::split(worker);
    let (done_tx, done_rx) = oneshot::channel();
    let deadline = Instant::now() + Duration::from_secs(2);
    let child = serve(
        worker_in,
        worker_out,
        |topology| {
            if topology.peer_count() != 1 {
                return Err(io::Error::other("wrong topology"));
            }
            let mut batch = Program::new();
            let task = batch.start(async { done_rx.await.map_err(io::Error::other) })?;
            batch.reach_and_wait(c"ready")?;
            batch.finish(task, Duration::from_secs(1))?;
            let mut program = Program::new();
            program.batch(batch)?;
            program.run(async { Ok(()) })?;
            Ok(program)
        },
        deadline,
    );
    let parent = async {
        let (mut reader, mut writer) = tokio::io::split(controller);
        let keys = [key()];
        send(
            &mut writer,
            ToHelper::Init(Init::new(&keys, TOPOLOGY).map_err(io::Error::other)?),
        )
        .await?;
        if receive(&mut reader).await? != FromHelper::BarrierReached(key()) {
            return Err(io::Error::other("missing barrier report"));
        }
        done_tx
            .send(())
            .map_err(|()| io::Error::other("background task dropped before finish"))?;
        send(&mut writer, ToHelper::BarrierCrossable(key())).await?;
        if receive(&mut reader).await? != FromHelper::Finished(1) {
            return Err(io::Error::other("unexpected result"));
        }
        writer.shutdown().await
    };
    let (child, parent) = tokio::join!(child, parent);
    parent?;
    child?;
    Ok(())
}

#[tokio::test]
async fn result_follows_an_interrupted_reach_without_corrupting_its_frame()
-> Result<(), Box<dyn std::error::Error>> {
    let (controller, worker) = tokio::io::duplex(5);
    let (worker_in, worker_out) = tokio::io::split(worker);
    let (fail_tx, fail_rx) = oneshot::channel();
    let deadline = Instant::now() + Duration::from_secs(2);
    let child = serve(
        worker_in,
        worker_out,
        |_| {
            let mut program = Program::new();
            let task = program.start(async {
                fail_rx.await.map_err(io::Error::other)?;
                Err(io::Error::other("local command failure"))
            })?;
            program.reach(c"ready")?;
            program.finish(task, Duration::from_secs(1))?;
            Ok(program)
        },
        deadline,
    );
    let parent = async {
        let (mut reader, mut writer) = tokio::io::split(controller);
        let keys = [key()];
        send(
            &mut writer,
            ToHelper::Init(Init::new(&keys, TOPOLOGY).map_err(io::Error::other)?),
        )
        .await?;
        let mut reach = [0; BARRIER_FRAME_LEN];
        let _length = reader.read_exact(&mut reach[..2]).await?;
        fail_tx
            .send(())
            .map_err(|()| io::Error::other("background task stopped before injection"))?;
        let _length = reader.read_exact(&mut reach[2..]).await?;
        if FromHelper::decode(&reach).map_err(io::Error::other)?
            != FromHelper::BarrierReached(key())
            || receive(&mut reader).await? != FromHelper::Finished(-1)
        {
            return Err(io::Error::other("interrupted frame or incorrect status"));
        }
        writer.shutdown().await
    };
    let (child, parent) = tokio::join!(child, parent);
    parent?;
    if !matches!(child, Err(PeerError::Command(error)) if error.to_string() == "local command failure")
    {
        return Err(io::Error::other("local command failure was lost").into());
    }
    Ok(())
}

#[tokio::test]
async fn controller_eof_drops_the_original_local_action() -> Result<(), Box<dyn std::error::Error>>
{
    let (controller, worker) = tokio::io::duplex(8);
    let (worker_in, worker_out) = tokio::io::split(worker);
    let deadline = Instant::now() + Duration::from_secs(2);
    let (started_tx, started_rx) = oneshot::channel();
    let (drop_tx, drop_rx) = oneshot::channel();
    struct NotifyOnDrop(Option<oneshot::Sender<()>>);
    impl Drop for NotifyOnDrop {
        fn drop(&mut self) {
            if let Some(sender) = self.0.take() {
                let _sent = sender.send(());
            }
        }
    }
    let child = serve(
        worker_in,
        worker_out,
        |_| {
            let mut program = Program::new();
            program.run(async {
                let _notify = NotifyOnDrop(Some(drop_tx));
                started_tx
                    .send(())
                    .map_err(|()| io::Error::other("parent disappeared"))?;
                std::future::pending::<io::Result<()>>().await
            })?;
            Ok(program)
        },
        deadline,
    );
    let parent = async {
        let (_reader, mut writer) = tokio::io::split(controller);
        send(
            &mut writer,
            ToHelper::Init(Init::new(&[], TOPOLOGY).map_err(io::Error::other)?),
        )
        .await?;
        started_rx.await.map_err(io::Error::other)?;
        writer.shutdown().await
    };
    let (child, parent) = tokio::join!(child, parent);
    parent?;
    if !matches!(child, Err(PeerError::ParentClosed)) || drop_rx.await.is_err() {
        return Err(io::Error::other("controller exit did not cancel its original action").into());
    }
    Ok(())
}
