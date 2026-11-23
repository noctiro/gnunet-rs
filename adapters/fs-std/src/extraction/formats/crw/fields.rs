//! CIFF values projected into the GNU metadata registry.

use time::OffsetDateTime;

use super::super::{Dimensions, IMAGE_ORIENTATION, ORIENTATION_LABELS};
use super::Order;

pub(super) fn geometry<E>(
    bytes: &[u8],
    order: Order,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(&geometry) = bytes.first_chunk::<28>() else {
        return Ok(());
    };
    if let (Some(width), Some(height)) = (order.long(&geometry[..4]), order.long(&geometry[4..8]))
        && let Some(size) = Dimensions::new(width, height)
    {
        size.emit(emit)?;
    }
    let Some(rotation) = order.long(&geometry[12..16]) else {
        return Ok(());
    };
    // CIFF encodes clockwise rotation in signed degrees.
    let label = match rotation.cast_signed() {
        0 => ORIENTATION_LABELS[0],
        90 | -270 => ORIENTATION_LABELS[5],
        180 | -180 => ORIENTATION_LABELS[2],
        270 | -90 => ORIENTATION_LABELS[7],
        _ => return Ok(()),
    };
    text(label.as_bytes(), IMAGE_ORIENTATION, limit, emit)
}

pub(super) fn make_model<E>(
    bytes: &[u8],
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let Some(make_end) = bytes.iter().position(|&byte| byte == 0) else {
        return Ok(());
    };
    text(&bytes[..make_end], 95, limit, emit)?;
    let model = &bytes[make_end + 1..];
    if let Some(model_end) = model.iter().position(|&byte| byte == 0) {
        text(&model[..model_end], 96, limit, emit)?;
    }
    Ok(())
}

pub(super) fn date<E>(
    bytes: &[u8],
    order: Order,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if bytes.len() < 8 {
        return Ok(());
    }
    let Some(date) = order
        .long(bytes)
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(i64::from(seconds)).ok())
    else {
        return Ok(());
    };
    let caption = format!(
        "{:04}:{:02}:{:02} {:02}:{:02}:{:02}",
        date.year(),
        u8::from(date.month()),
        date.day(),
        date.hour(),
        date.minute(),
        date.second()
    );
    text(caption.as_bytes(), 58, limit, emit)
}

pub(super) fn text<E>(
    bytes: &[u8],
    kind: u32,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    let bytes = bytes.split(|&byte| byte == 0).next().unwrap_or_default();
    if !bytes.is_empty() && bytes.len() <= limit && std::str::from_utf8(bytes).is_ok() {
        emit(kind, bytes)?;
    }
    Ok(())
}

pub(super) fn camera_settings<E>(
    bytes: &[u8],
    order: Order,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    const MACRO: &[&str] = &["", "On", "Off"];
    const QUALITY: &[&str] = &[
        "unknown",
        "Economy",
        "Normal",
        "Fine",
        "RAW",
        "Superfine",
        "",
        "CRAW",
    ];
    const EXPOSURE: &[&str] = &[
        "Easy shooting (Auto)",
        "Program (P)",
        "Shutter priority (Tv)",
        "Aperture priority (Av)",
        "Manual (M)",
        "A-DEP",
        "M-DEP",
        "Bulb",
    ];
    for (index, kind, table) in [(1, 107, MACRO), (3, 108, QUALITY), (20, 105, EXPOSURE)] {
        label(word(bytes, order, index), kind, table, limit, emit)?;
    }
    Ok(())
}

pub(super) fn shot_info<E>(
    bytes: &[u8],
    order: Order,
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    const BALANCE: &[&str] = &[
        "Auto",
        "Daylight",
        "Cloudy",
        "Tungsten",
        "Fluorescent",
        "Flash",
        "Custom",
        "Black & White",
        "Shade",
        "Manual Temperature (Kelvin)",
        "PC Set 1",
        "PC Set 2",
        "PC Set 3",
        "",
        "Daylight Fluorescent",
        "Custom 1",
        "Custom 2",
        "Underwater",
        "Custom 3",
        "Custom 3",
        "PC Set 4",
        "PC Set 5",
        "",
        "Auto (ambience priority)",
    ];

    if let Some(iso) = word(bytes, order, 2).map(|value| 3.125 * canon_ev(i32::from(value)).exp2())
        && (1.0..=f64::from(u32::MAX)).contains(&iso)
    {
        text(iso.round().to_string().as_bytes(), 104, limit, emit)?;
    }
    label(word(bytes, order, 7), 109, BALANCE, limit, emit)?;
    if let Some(bias) = word(bytes, order, 15).map(|value| canon_ev(i32::from(value.cast_signed())))
        && (-2.0..=2.0).contains(&bias)
    {
        let caption = if bias.fract() == 0.0 {
            format!("{bias:.0} EV")
        } else {
            format!("{bias:.2} EV")
        };
        text(caption.as_bytes(), 101, limit, emit)?;
    }
    if let Some(f) =
        word(bytes, order, 21).map(|value| (canon_ev(i32::from(value.cast_signed())) / 2.0).exp2())
    {
        let factor = 10_f64.powi(1 - f.log10().floor() as i32);
        text(
            format!("F{}", (f * factor).round() / factor).as_bytes(),
            98,
            limit,
            emit,
        )?;
    }
    if let Some(tv) = word(bytes, order, 22).map(|value| canon_ev(i32::from(value.cast_signed())))
        && tv.abs().exp2().is_finite()
    {
        let shutter = if tv > 0.0 {
            format!("1/{:.0} s", tv.exp2())
        } else {
            format!("{:.0} s", (-tv).exp2())
        };
        text(shutter.as_bytes(), 97, limit, emit)?;
    }
    Ok(())
}

fn label<E>(
    value: Option<u16>,
    kind: u32,
    table: &[&str],
    limit: usize,
    emit: &mut impl FnMut(u32, &[u8]) -> Result<(), E>,
) -> Result<(), E> {
    if let Some(label) = value.and_then(|index| table.get(usize::from(index))) {
        text(label.as_bytes(), kind, limit, emit)?;
    }
    Ok(())
}

fn word(bytes: &[u8], order: Order, index: usize) -> Option<u16> {
    order.short(bytes.get(index * 2..)?)
}

fn canon_ev(value: i32) -> f64 {
    let absolute = value.unsigned_abs();
    let whole = absolute / 32;
    let fraction = match (whole, absolute % 32) {
        (_, 0x0c) => 1.0 / 3.0,
        (_, 0x14) => 2.0 / 3.0,
        (5, 0x08) => 5.0 / 16.0,
        (_, remainder) => f64::from(remainder) / 32.0,
    };
    (f64::from(whole) + fraction).copysign(f64::from(value))
}
