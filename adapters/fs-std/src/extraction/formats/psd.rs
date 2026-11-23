//! Adobe Photoshop document headers and image resources.

use super::{Dimensions, Input, iptc, photoshop, xmp};

const HEADER_BYTES: usize = 26;
const LENGTH_BYTES: usize = 4;

pub(super) fn visit<E>(
    mut input: Input<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(header) = input.range(0, HEADER_BYTES + LENGTH_BYTES)? else {
        return Ok(());
    };
    let Some(size) = dimensions(header) else {
        return Ok(());
    };
    size.emit(emit)?;

    let Some(color_len) = header[HEADER_BYTES..]
        .first_chunk()
        .copied()
        .map(u32::from_be_bytes)
    else {
        return Ok(());
    };
    let length_at = (HEADER_BYTES + LENGTH_BYTES) as u64 + u64::from(color_len);
    let Some(length) = input
        .range(length_at, LENGTH_BYTES)?
        .and_then(|data| data.first_chunk().copied())
        .map(u32::from_be_bytes)
    else {
        return Ok(());
    };
    let resources_at = length_at + LENGTH_BYTES as u64;
    if resources_at + u64::from(length) > input.extent {
        return Ok(());
    }
    let Ok(extent) = usize::try_from(length) else {
        return Ok(());
    };
    let Some([iptc_resource, xmp_resource]) = photoshop::resources(
        extent,
        [photoshop::IPTC_IIM, photoshop::XMP],
        |start, target| -> Result<bool, E> {
            let Some(bytes) = input.range(resources_at + start as u64, target.len())? else {
                return Ok(false);
            };
            target.copy_from_slice(bytes);
            Ok(true)
        },
    )?
    else {
        return Ok(());
    };
    if let Some(resource) = iptc_resource
        && let Some(bytes) = input.range(resources_at + resource.start as u64, resource.len())?
        && let Some(profile) = iptc::Profile::parse(bytes, 0)
    {
        profile.emit(limit, emit)?;
    }
    if let Some(resource) = xmp_resource
        && let Some(bytes) = input.range(resources_at + resource.start as u64, resource.len())?
    {
        xmp::visit(bytes, limit, emit)?;
    }
    Ok(())
}

fn dimensions(header: &[u8]) -> Option<Dimensions> {
    let header = header.first_chunk::<HEADER_BYTES>()?;
    if &header[..4] != b"8BPS" || header[6..12] != [0; 6] {
        return None;
    }
    let maximum = match u16::from_be_bytes(*header[4..].first_chunk()?) {
        1 => 30_000,
        2 => 300_000,
        _ => return None,
    };
    let channels = u16::from_be_bytes(*header[12..].first_chunk()?);
    let height = u32::from_be_bytes(*header[14..].first_chunk()?);
    let width = u32::from_be_bytes(*header[18..].first_chunk()?);
    let depth = u16::from_be_bytes(*header[22..].first_chunk()?);
    let mode = u16::from_be_bytes(*header[24..].first_chunk()?);
    if !(1..=56).contains(&channels)
        || !matches!(depth, 1 | 8 | 16 | 32)
        || !matches!(mode, 0..=4 | 7..=9)
        || width > maximum
        || height > maximum
    {
        return None;
    }
    Dimensions::new(width, height)
}
