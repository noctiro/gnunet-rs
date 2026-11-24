//! Hosted storage preserves the maximum official request on a small thread stack.
use super::*;
use gnunet_wire::official::{Frame, message_type};

#[test]
fn max_wire_selector_fits_on_a_small_host_stack() -> Result<(), IpcError> {
    std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            const MAX: usize = u16::MAX as usize;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()?;
            let _entered = runtime.enter();
            let mut instance = Instance::new();
            let mut owner = StatisticsHandle::<16, MAX, 4, 16, 8>::new(
                &mut instance,
                "unused.sock",
                b"s",
                true,
                Limits::default(),
            )?
            .ok_or(Error::NotReady)?;
            let name = vec![b'n'; MAX - 7];
            owner.get(Selector {
                subsystem: b"s",
                name: &name,
            })?;
            let envelope = &owner.scheduler.envelopes[owner.scheduler.head];
            let size = envelope.frame.ok_or(Error::NotReady)?.len;
            let frame = Frame::decode(&envelope.bytes[..size])?;
            if size != MAX
                || frame.header().message_type() != message_type::STATISTICS_GET
                || !frame.payload().starts_with(b"s\0")
                || frame.payload()[2..frame.payload().len() - 1] != name
                || frame.payload().last() != Some(&0)
            {
                return Err(Error::InvalidInput.into());
            }
            Ok(())
        })?
        .join()
        .map_err(|_| io::Error::other("STATISTICS test thread panicked"))?
}
