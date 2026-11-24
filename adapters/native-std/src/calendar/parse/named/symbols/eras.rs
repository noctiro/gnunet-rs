//! Native era names for the same calendar used by date conversion.
use super::super::{calendar_text, callback_text};
use super::{Symbols, nls};
use crate::calendar_pattern::Word;
use std::{
    io,
    ops::RangeInclusive,
    panic::{AssertUnwindSafe, catch_unwind},
    ptr,
};
use windows_sys::Win32::Globalization::{
    CAL_SABBREVERASTRING, CAL_SERASTRING, EnumCalendarInfoExEx,
};

pub(super) fn append(
    symbols: &mut Symbols,
    locale: &nls::Name,
    calendar: u32,
    eras: RangeInclusive<u16>,
) -> io::Result<()> {
    let newest = *eras.end();
    let count = usize::from(newest - *eras.start()) + 1;
    for property in [CAL_SERASTRING, CAL_SABBREVERASTRING] {
        let current = calendar_text(locale, calendar, property)?;
        if count == 1 {
            symbols.push(Word::Era, newest, current)?;
            continue;
        }
        // NLS returns historical names newest first. Confirm the inventory
        // against the converter's era range and the current era property.
        let names = enumerate(locale, calendar, property, count)?;
        if names.first() != Some(&current) {
            return Err(invalid_inventory());
        }
        for (era, name) in eras.clone().rev().zip(names) {
            symbols.push(Word::Era, era, name)?;
        }
    }
    Ok(())
}

fn invalid_inventory() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "inconsistent native calendar era names",
    )
}

struct Inventory {
    calendar: u32,
    count: usize,
    names: Vec<Vec<u16>>,
    failure: Option<io::Error>,
}

#[expect(
    unsafe_code,
    reason = "The NLS enumeration borrows one live exclusive inventory and a terminated callback string; panic containment preserves the native ABI"
)]
unsafe extern "system" fn record(
    value: *const u16,
    calendar: u32,
    _: *const u16,
    context: isize,
) -> i32 {
    // SAFETY: the synchronous enumerator passes the original exclusive owner.
    let inventory = unsafe { &mut *(context as *mut Inventory) };
    match catch_unwind(AssertUnwindSafe(|| {
        if calendar != inventory.calendar || inventory.names.len() == inventory.count {
            return Err(invalid_inventory());
        }
        // SAFETY: the callback's wide string remains live through this call.
        let text = unsafe { callback_text(value) }?;
        if text.is_empty() {
            return Err(invalid_inventory());
        }
        inventory.names.push(text);
        Ok(())
    })) {
        Ok(Ok(())) => 1,
        Ok(Err(error)) => {
            inventory.failure = Some(error);
            0
        }
        Err(_) => {
            inventory.failure = Some(io::Error::other("native era callback panicked"));
            0
        }
    }
}

#[expect(
    unsafe_code,
    reason = "NLS borrows a validated terminated locale and an exclusive stack inventory for synchronous enumeration"
)]
fn enumerate(
    locale: &nls::Name,
    calendar: u32,
    property: u32,
    count: usize,
) -> io::Result<Vec<Vec<u16>>> {
    let mut names = Vec::new();
    names
        .try_reserve_exact(count)
        .map_err(|_| io::ErrorKind::OutOfMemory)?;
    let mut inventory = Inventory {
        calendar,
        count,
        names,
        failure: None,
    };
    // SAFETY: callback and context remain valid until enumeration returns.
    let ok = unsafe {
        EnumCalendarInfoExEx(
            Some(record),
            locale.as_ptr(),
            calendar,
            ptr::null(),
            property,
            (&mut inventory as *mut Inventory) as isize,
        )
    };
    if let Some(error) = inventory.failure {
        return Err(error);
    }
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    if inventory.names.len() != count {
        return Err(invalid_inventory());
    }
    Ok(inventory.names)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        calendar::parse::named::Conversion,
        calendar_pattern::{Budget, Names},
    };
    use windows_sys::Win32::Globalization::CAL_JAPAN;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check native Japanese names against historical era IDs independently of NLS enumeration order"
    )]
    fn historical_japanese_names_select_the_original_era() -> io::Result<()> {
        let name = nls::resolve_name(&"ja-JP".encode_utf16().collect::<Vec<_>>())?;
        let japanese = Conversion::load(CAL_JAPAN)?;
        let mut symbols = Symbols {
            name: name.clone(),
            entries: Vec::new(),
        };
        append(&mut symbols, &name, CAL_JAPAN, japanese.eras())?;
        for (text, era) in [("明治", 1), ("平成", 4), ("平", 4)] {
            let text: Vec<_> = text.encode_utf16().collect();
            assert_eq!(
                symbols.prefix(&text, Word::Era, &mut Budget::new())?,
                Some((era, text.len()))
            );
        }
        Ok(())
    }
}
