//! Check the actual linked image before reporting a successful driver build.
use crate::{Result, invalid, sdk::Target};
use object::{LittleEndian, Object, pe, read::pe::PeFile64};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn inspect(target: &Target, bytes: &[u8], map: &str) -> Result<Value> {
    use pe::*;

    let image = PeFile64::parse(bytes)?;
    let header = image.nt_headers();
    let file_flags = header.file_header.characteristics.get(LittleEndian);
    let optional = &header.optional_header;
    let dll_flags = optional.dll_characteristics.get(LittleEndian);
    let required_dll_flags =
        IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    if header.file_header.machine.get(LittleEndian) != target.pe_machine
        || optional.subsystem.get(LittleEndian) != IMAGE_SUBSYSTEM_NATIVE
        || !file_flags.contains(IMAGE_FILE_EXECUTABLE_IMAGE)
        || file_flags.contains(IMAGE_FILE_DLL)
        || !dll_flags.contains(required_dll_flags)
        || image
            .data_directory(IMAGE_DIRECTORY_ENTRY_SECURITY)
            .is_some()
    {
        return Err(invalid(format!(
            "expected an unsigned native {} executable with ASLR and NX",
            target.pe_name
        ))
        .into());
    }
    for (index, name) in [
        (IMAGE_DIRECTORY_ENTRY_IMPORT, "imports"),
        (IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, "WDK load configuration"),
        (IMAGE_DIRECTORY_ENTRY_EXCEPTION, "unwind data"),
        (IMAGE_DIRECTORY_ENTRY_BASERELOC, "relocations"),
    ] {
        if image
            .data_directory(index)
            .is_none_or(|data| data.size.get(LittleEndian) == 0)
        {
            return Err(invalid(format!("driver image is missing {name}")).into());
        }
    }

    let mut addresses = BTreeMap::new();
    for symbol in [
        "GsDriverEntry",
        "DriverEntry",
        "_load_config_used",
        "WdmlibIoCreateDeviceSecure",
    ] {
        let address = map
            .lines()
            .find_map(|line| {
                let mut fields = line.split_whitespace();
                if fields.next()?.contains(':') && fields.next()? == symbol {
                    fields.next()
                } else {
                    None
                }
            })
            .ok_or_else(|| invalid(format!("link map is missing {symbol}")))?;
        addresses.insert(symbol, u64::from_str_radix(address, 16)?);
    }
    let load_config = image
        .data_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG)
        .ok_or_else(|| invalid("missing load configuration"))?;
    let load_config_rva = load_config.virtual_address.get(LittleEndian);
    if image.entry() != addresses["GsDriverEntry"]
        || addresses["GsDriverEntry"] == addresses["DriverEntry"]
        || Some(addresses["_load_config_used"])
            != image
                .relative_address_base()
                .checked_add(u64::from(load_config_rva))
    {
        return Err(invalid("PE entry or load configuration differs from the WDK link map").into());
    }

    let mut imports = BTreeMap::<String, BTreeSet<&str>>::new();
    for import in image.imports()? {
        let import = import?;
        let name = import
            .name()
            .into_name()
            .ok_or_else(|| invalid("driver image has an import by ordinal"))?;
        imports
            .entry(std::str::from_utf8(import.library())?.to_ascii_lowercase())
            .or_default()
            .insert(std::str::from_utf8(name)?);
    }
    let expected: [(&str, &[&str]); 3] = [
        (
            "ntoskrnl.exe",
            &["ExAllocatePool2", "IoDeleteDevice", "KeBugCheckEx"],
        ),
        (
            "fwpkclnt.sys",
            &[
                "FwpsCalloutRegister0",
                "FwpsCalloutUnregisterById0",
                "FwpmBfeStateUnsubscribeChanges0",
            ],
        ),
        ("ndis.sys", &["NdisFreeNetBufferListPool"]),
    ];
    if imports.len() != expected.len()
        || expected.iter().any(|(module, symbols)| {
            imports
                .get(*module)
                .is_none_or(|actual| symbols.iter().any(|symbol| !actual.contains(symbol)))
        })
    {
        return Err(
            invalid("linked image does not have the expected kernel/WFP/NDIS imports").into(),
        );
    }
    Ok(
        json!({"format": "PE32+", "machine": target.pe_name, "subsystem": "native",
        "entry": image.entry(), "load_config_rva": load_config_rva,
        "symbols": addresses, "imports": imports}),
    )
}
