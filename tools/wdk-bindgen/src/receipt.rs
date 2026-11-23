use crate::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Read,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, Default)]
pub struct Headers(Arc<Mutex<BTreeSet<PathBuf>>>);

impl bindgen::callbacks::ParseCallbacks for Headers {
    fn include_file(&self, filename: &str) {
        let mut paths = match self.0.lock() {
            Ok(paths) => paths,
            Err(poisoned) => poisoned.into_inner(),
        };
        paths.insert(PathBuf::from(filename));
    }
}

impl Headers {
    pub fn files(&self) -> Result<Vec<PathBuf>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| crate::invalid("header-input collection poisoned"))?
            .iter()
            .cloned()
            .collect())
    }
}

fn digest(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(64);
    for &byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 15)]));
    }
    text
}

pub fn file(path: &Path) -> Result<Value> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = match file.read(&mut buffer) {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            result => result?,
        };
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
        bytes += read as u64;
    }
    Ok(
        json!({"path": path.display().to_string(), "bytes": bytes, "sha256": hex(&digest.finalize())}),
    )
}

pub fn write(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    fs::write(path, bytes)?;
    Ok(())
}

pub fn sources() -> Value {
    let sources: &[(&str, &[u8])] = &[
        ("Cargo.toml", include_bytes!("../Cargo.toml")),
        ("Cargo.lock", include_bytes!("../Cargo.lock")),
        ("src/main.rs", include_bytes!("main.rs")),
        ("src/cli.rs", include_bytes!("cli.rs")),
        ("src/command.rs", include_bytes!("command.rs")),
        ("src/driver.rs", include_bytes!("driver.rs")),
        ("src/driver/image.rs", include_bytes!("driver/image.rs")),
        ("src/sdk.rs", include_bytes!("sdk.rs")),
        ("src/includes.rs", include_bytes!("includes.rs")),
        ("src/generate.rs", include_bytes!("generate.rs")),
        ("src/receipt.rs", include_bytes!("receipt.rs")),
        ("src/allowlist.rs", include_bytes!("allowlist.rs")),
        ("sdk/wrapper.h", include_bytes!("../sdk/wrapper.h")),
        ("sdk/wrappers.c", include_bytes!("../sdk/wrappers.c")),
    ];
    Value::Array(
        sources
            .iter()
            .map(|(name, bytes)| json!({"source": name, "sha256": digest(bytes)}))
            .collect(),
    )
}
