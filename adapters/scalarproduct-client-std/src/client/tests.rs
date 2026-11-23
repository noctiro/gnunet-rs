use super::{
    Alarm, Bounds, Chunk, Client, EndpointSource, Error, Fault, Limits, Role, WriteProgress,
};
use gnunet_service_runtime::clock::AbsoluteTime;
use std::{path::PathBuf, time::Duration};
use tokio::time::Instant;

#[test]
fn late_whole_write_keeps_actual_input_exposure() -> Result<(), Box<dyn std::error::Error>> {
    let source = EndpointSource::unix(PathBuf::from("unused-scalarproduct-client"));
    let original = Bounds::after(source.clock().as_ref(), Duration::from_secs(30))?;
    let mut client = Client::new(
        source,
        Role::Bob { session: [0; 64] },
        vec![[0; super::ELEMENT_BYTES]],
        Limits::default(),
        original,
    )?;
    let chunk = Chunk { start: 0, count: 1 };
    client.pending = Some(chunk);
    let write_target = Bounds::from_targets(
        AbsoluteTime::from_micros(original.expires()),
        Instant::now(),
    )?;
    client.write = Some(Alarm::new(write_target));
    if !matches!(
        client.record_write(WriteProgress {
            origin: chunk,
            bytes: 152,
            complete: true,
        }),
        Err(Error::Protocol(Fault::Deadline))
    ) {
        return Err("an overdue whole write did not preserve its original deadline".into());
    }
    let receipt = client.receipt();
    if receipt.frames_written != 1
        || receipt.written_bytes != 152
        || receipt.partial_frame_bytes != 0
        || !receipt.all_input_written
    {
        return Err(format!("wrong input exposure: {receipt:?}").into());
    }
    Ok(())
}
