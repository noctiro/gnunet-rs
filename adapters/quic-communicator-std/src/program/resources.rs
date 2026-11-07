//! Fixed caller-owned receive bodies. TX MTUs never size incoming bodies.
use super::{Failure, settings::Settings};
use zeroize::Zeroizing;
type BodyPool = Vec<Zeroizing<Vec<u8>>>;
/// Actual retained payload capacities plus body-vector metadata. This measures
/// this explicit loan pool, not RSS, allocator headers or Quinn's own windows.
pub(super) fn bodies(settings: &Settings) -> Result<(BodyPool, usize), Failure> {
    let per = match settings.profile {
        crate::tls::Profile::Raw => 1,
        crate::tls::Profile::Http3 => settings
            .limits
            .h3_polls
            .checked_add(2)
            .ok_or("H3 slots overflow")?,
    };
    let size = match settings.profile {
        crate::tls::Profile::Raw => settings.limits.raw_body,
        crate::tls::Profile::Http3 => settings.limits.h3_body,
    };
    let count = settings
        .limits
        .backend
        .connections
        .checked_mul(per)
        .ok_or("frame count overflow")?;
    let payload = count.checked_mul(size).ok_or("frame pool overflow")?;
    let metadata = count
        .checked_mul(
            std::mem::size_of::<gnunet_transport_quic::h3::Slot<'_, '_>>()
                + std::mem::size_of::<Zeroizing<Vec<u8>>>(),
        )
        .ok_or("metadata overflow")?;
    let handles = settings
        .limits
        .backend
        .connections
        .checked_mul(std::mem::size_of::<Option<&mut [u8]>>())
        .ok_or("loan metadata overflow")?;
    if payload
        .checked_add(metadata)
        .and_then(|n| n.checked_add(handles))
        .ok_or("frame budget overflow")?
        > settings.memory
    {
        return Err("configured receive pool exceeds FRAME_POOL_BYTES".into());
    }
    let mut bodies = Vec::new();
    bodies.try_reserve_exact(count)?;
    for _ in 0..count {
        let mut b = Zeroizing::new(Vec::new());
        b.try_reserve_exact(size)?;
        b.resize(size, 0);
        bodies.push(b)
    }
    let metadata = bodies
        .capacity()
        .checked_mul(std::mem::size_of::<Zeroizing<Vec<u8>>>())
        .ok_or("allocated metadata overflow")?;
    let actual = bodies.iter().try_fold(metadata, |sum, b| {
        sum.checked_add(b.capacity())
            .ok_or("allocated pool overflow")
    })?;
    if actual > settings.memory {
        return Err("allocated receive pool exceeds FRAME_POOL_BYTES".into());
    }
    Ok((bodies, actual))
}
/// Account the actual vector capacities allocated by the external caller after
/// it has constructed either raw loans or fresh H3 slots. Every byte bound is
/// checked before Runtime can bind/admit a source.
pub(super) fn loans(
    settings: &Settings,
    body_bytes: usize,
    slots: usize,
    handles: usize,
) -> Result<(), Failure> {
    let metadata = slots
        .checked_mul(std::mem::size_of::<gnunet_transport_quic::h3::Slot<'_, '_>>())
        .and_then(|n| {
            handles
                .checked_mul(std::mem::size_of::<Option<&mut [u8]>>())
                .and_then(|m| n.checked_add(m))
        })
        .ok_or("allocated loan metadata overflow")?;
    if body_bytes
        .checked_add(metadata)
        .ok_or("allocated loan pool overflow")?
        > settings.memory
    {
        return Err("allocated receive loans exceed FRAME_POOL_BYTES".into());
    }
    Ok(())
}
