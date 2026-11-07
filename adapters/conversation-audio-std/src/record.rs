use crate::{
    Error, Limits, RATE, RECORD_SAMPLES, Report, buffer, framing, increment,
    native::{Encoder, Pulse},
    ogg::Mux,
};
use gnunet_types::Error as Fault;
use std::io;
/// Run actual standard microphone capture/Opus/Ogg output in an independent
/// helper process. This is deliberately blocking and continuous. Parent owns
/// real signal/timeout termination and wait/reap; no SDK background task exists.
pub fn record(limits: Limits) -> Result<Report, Error> {
    let limits = limits.validate()?;
    let mut encoder = Encoder::new(limits)?;
    let mut serial = [0; 4];
    if let Err(error) = getrandom::fill(&mut serial) {
        serial.fill(0);
        return Err(Error::Entropy(error));
    }
    let mut mux = Mux::new(u32::from_le_bytes(serial), limits)?;
    let mut pcm = buffer::<f32>(RECORD_SAMPLES)?;
    let mut raw = buffer::<u8>(RECORD_SAMPLES * 4)?;
    let mut packet = buffer::<u8>(1024)?;
    let mut microphone = Pulse::new(true, 1)?;
    let stdout = io::stdout();
    let mut output = stdout.lock();
    let mut report = Report::default();
    let mut head = [0; 19];
    head[..8].copy_from_slice(b"OpusHead");
    head[8] = 1;
    head[9] = 1;
    head[12..16].copy_from_slice(&RATE.to_le_bytes());
    // Preskip0/gain0/map0 are the actual selected official record profile.
    framing::write_frame(&mut output, mux.packet(&head, 2, 0)?, limits)?;
    increment(&mut report.frames, 1)?;
    increment(&mut report.pages, 1)?;
    const VENDOR: &[u8] = b"gnunet-rs/libopus";
    let mut tags = [0; 16 + VENDOR.len()];
    tags[..8].copy_from_slice(b"OpusTags");
    tags[8..12].copy_from_slice(
        &u32::try_from(VENDOR.len())
            .map_err(|_| Fault::Overflow)?
            .to_le_bytes(),
    );
    tags[12..12 + VENDOR.len()].copy_from_slice(VENDOR);
    framing::write_frame(&mut output, mux.packet(&tags, 0, 0)?, limits)?;
    increment(&mut report.frames, 1)?;
    increment(&mut report.pages, 1)?;
    let mut granule = 0u64;
    loop {
        microphone.read(&mut raw)?;
        for (sample, bytes) in pcm.iter_mut().zip(raw.as_chunks::<4>().0.iter()) {
            *sample = f32::from_le_bytes(*bytes);
        }
        let n = encoder.encode(&pcm, &mut packet)?;
        granule = granule
            .checked_add(u64::try_from(RECORD_SAMPLES).map_err(|_| Fault::Overflow)?)
            .ok_or(Fault::Overflow)?;
        increment(
            &mut report.recorded_samples,
            u64::try_from(RECORD_SAMPLES).map_err(|_| Fault::Overflow)?,
        )?;
        framing::write_frame(&mut output, mux.packet(&packet[..n], 0, granule)?, limits)?;
        increment(&mut report.frames, 1)?;
        increment(&mut report.pages, 1)?;
        raw.fill(0);
        pcm.fill(0.0);
        packet.fill(0);
    }
}
