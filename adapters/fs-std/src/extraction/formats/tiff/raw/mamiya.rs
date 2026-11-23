//! Mamiya ZD Electronic Format, identified from its full-size TIFF sensor directory.

use super::{Compression, Selection, Tiff, maker};
use crate::extraction::formats::tiff::{primary, reader::Kind};

pub(in crate::extraction::formats::tiff) fn is_zd<E>(
    tiff: &mut Tiff<'_, impl FnMut(u64, &mut [u8]) -> Result<(), E>>,
    root: &Selection,
    image: &Selection,
    compression: Compression,
) -> Result<bool, E> {
    if compression.value() != Some(1) || primary::photometric(tiff, image)? != Some(32803) {
        return Ok(false);
    }
    if primary::bits_per_sample(tiff, image)? != Some(12) {
        return Ok(false);
    }
    for (tag, accepted) in [
        (maker::MAKE, &["Mamiya", "Mamiya-OP Co., Ltd."][..]),
        (
            maker::MODEL,
            &["Mamiya ZD", "Mamiya ZD Back", "ZD", "ZD Back"][..],
        ),
    ] {
        let Some(field) = root.find(tag).filter(|field| {
            !field.duplicate && field.row.kind() == Kind::Ascii && field.row.len() <= 32
        }) else {
            return Ok(false);
        };
        let name = tiff
            .read_field(&field.row)?
            .and_then(|entry| entry.string());
        if !name.is_some_and(|name| {
            accepted
                .iter()
                .any(|candidate| name.trim_ascii().eq_ignore_ascii_case(candidate))
        }) {
            return Ok(false);
        }
    }
    primary::Family::Tiff.full_image(tiff, image)
}
