//! Present the SDK's Windows include namespace on every build host.
use crate::{Result, invalid, receipt, sdk};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, btree_map::Entry},
    fs,
    path::{Path, PathBuf},
};

pub fn write(output: &Path, paths: &[PathBuf]) -> Result<()> {
    for path in paths {
        if !path.is_dir() {
            return Err(invalid(format!(
                "missing actual include directory: {}",
                path.display()
            ))
            .into());
        }
    }
    // km/crt remains a distinct search path. Its entries already belong to km
    // in the overlay, so Clang sees only one mapping for each original file.
    let roots = paths
        .iter()
        .filter(|path| {
            !paths
                .iter()
                .any(|parent| parent != *path && path.starts_with(parent))
        })
        .map(|path| directory(path, sdk::utf8(path)?))
        .collect::<Result<Vec<_>>>()?;
    receipt::write(
        output,
        &json!({
            "version": 0,
            "case-sensitive": false,
            "use-external-names": true,
            "roots": roots,
        }),
    )
}

fn directory(path: &Path, name: String) -> Result<Value> {
    let mut entries = BTreeMap::new();
    for child in fs::read_dir(path)? {
        let child = child?;
        let original = child.path();
        let name = child.file_name().into_string().map_err(|_| {
            invalid(format!(
                "SDK include name is not UTF-8: {}",
                original.display()
            ))
        })?;
        let Entry::Vacant(slot) = entries.entry(name.to_ascii_lowercase()) else {
            return Err(invalid(format!(
                "ambiguous case-insensitive SDK include: {}",
                original.display()
            ))
            .into());
        };
        let kind = child.file_type()?;
        let value = if kind.is_dir() {
            directory(&original, name)?
        } else if kind.is_file() {
            json!({"type": "file", "name": name, "external-contents": sdk::utf8(&original)?})
        } else {
            return Err(invalid(format!(
                "unexpected SDK include entry: {}",
                original.display()
            ))
            .into());
        };
        slot.insert(value);
    }
    Ok(json!({
        "type": "directory",
        "name": name,
        "contents": entries.into_values().collect::<Vec<_>>(),
    }))
}
