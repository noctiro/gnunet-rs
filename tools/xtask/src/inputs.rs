//! Complete source/specification input fingerprints, without retained per-file reports.
use std::{error::Error, fs, path::Path};

pub(crate) fn fingerprint() -> Result<(String, String), Box<dyn Error>> {
    let mut source = Vec::new();
    let mut spec = Vec::new();
    for directory in [
        "crates", "adapters", "apps", "tools", "tests", ".cargo", ".github",
    ] {
        collect_files(Path::new(directory), &mut source)?;
    }
    for file in [
        "Cargo.toml",
        "Cargo.lock",
        "rust-toolchain.toml",
        "ARCHITECTURE.md",
        "README.md",
        "rustfmt.toml",
    ] {
        source.push(Path::new(file).to_path_buf());
    }
    collect_files(Path::new("spec"), &mut spec)?;
    Ok((digest_files(source)?, digest_files(spec)?))
}
/// Normative files excluding the ledger that embeds verification-report hashes.
/// Its normative owner projection is bound separately to avoid a hash cycle.
pub(crate) fn normative_fingerprint(root: &Path) -> Result<String, Box<dyn Error>> {
    let mut files = Vec::new();
    collect_files(&root.join("spec"), &mut files)?;
    files.retain(|path| path != &root.join("spec/gnunet/conformance.json"));
    // Path::Ord compares components: `gnunet/file` precedes `gnunet-client/file`.
    // The shared fingerprint contract sorts the complete UTF-8 path bytes.
    files.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
    let mut digest = [0; 32];
    for path in files {
        let data = fs::read(&path)?;
        let name = path
            .strip_prefix(root)?
            .to_str()
            .ok_or("non-UTF8 normative path")?;
        digest = gnunet_crypto::hash256_parts(&[
            &digest,
            &(name.len() as u64).to_be_bytes(),
            name.as_bytes(),
            &(data.len() as u64).to_be_bytes(),
            &data,
        ]);
    }
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn collect_files(path: &Path, output: &mut Vec<std::path::PathBuf>) -> Result<(), Box<dyn Error>> {
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if kind.is_symlink() {
            return Err(format!(
                "source/normative fingerprint refuses symbolic link: {}",
                entry.path().display()
            )
            .into());
        }
        if kind.is_dir() {
            if entry.file_name() != "target"
                && entry.file_name() != ".git"
                && entry.file_name() != "__pycache__"
            {
                collect_files(&entry.path(), output)?;
            }
        } else {
            output.push(entry.path());
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn symbolic_normative_inputs_cannot_disappear_from_the_fingerprint()
    -> Result<(), Box<dyn Error>> {
        let root =
            std::env::temp_dir().join(format!("gnunet-normative-links-{}", std::process::id()));
        fs::create_dir(&root)?;
        fs::create_dir(root.join("spec"))?;
        fs::write(root.join("untracked-contract"), b"contract")?;
        std::os::unix::fs::symlink(root.join("untracked-contract"), root.join("spec/contract"))?;
        let rejected = normative_fingerprint(&root).is_err();
        fs::remove_file(root.join("spec/contract"))?;
        fs::write(root.join("spec/contract"), b"first")?;
        let first = normative_fingerprint(&root)?;
        fs::write(root.join("spec/contract"), b"changed")?;
        let changed = normative_fingerprint(&root)?;
        fs::remove_dir_all(root)?;
        if !rejected || first == changed {
            return Err("normative input escaped freshness checks".into());
        }
        Ok(())
    }

    #[test]
    fn source_and_normative_order_is_full_path_bytes_not_components() -> Result<(), Box<dyn Error>>
    {
        let root =
            std::env::temp_dir().join(format!("gnunet-input-byte-order-{}", std::process::id()));
        fs::create_dir(&root)?;
        fs::create_dir_all(root.join("spec/api"))?;
        fs::write(root.join("spec/api.json"), b"a")?;
        fs::write(root.join("spec/api/header"), b"b")?;
        let files = [root.join("spec/api.json"), root.join("spec/api/header")];
        let mut expected_source = [0; 32];
        let mut expected_spec = [0; 32];
        for (path, relative, data) in [
            (&files[0], "spec/api.json", b"a".as_slice()),
            (&files[1], "spec/api/header", b"b".as_slice()),
        ] {
            let name = path.to_str().ok_or("non-UTF8 test path")?;
            expected_source = gnunet_crypto::hash256_parts(&[
                &expected_source,
                &(name.len() as u64).to_be_bytes(),
                name.as_bytes(),
                &(data.len() as u64).to_be_bytes(),
                data,
            ]);
            expected_spec = gnunet_crypto::hash256_parts(&[
                &expected_spec,
                &(relative.len() as u64).to_be_bytes(),
                relative.as_bytes(),
                &(data.len() as u64).to_be_bytes(),
                data,
            ]);
        }
        let encode = |bytes: [u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
        let actual_source = digest_files(files.into())?;
        let actual_spec = normative_fingerprint(&root)?;
        fs::remove_dir_all(&root)?;
        if actual_source != encode(expected_source) || actual_spec != encode(expected_spec) {
            return Err("fingerprint order differs from the shared full-path byte contract".into());
        }
        Ok(())
    }
}
fn digest_files(mut files: Vec<std::path::PathBuf>) -> Result<String, Box<dyn Error>> {
    files.sort_by(|a, b| {
        a.as_os_str()
            .as_encoded_bytes()
            .cmp(b.as_os_str().as_encoded_bytes())
    });
    let mut digest = [0; 32];
    for path in files {
        let data = fs::read(&path)?;
        let name = path.to_str().ok_or("non-UTF8 source path")?;
        digest = gnunet_crypto::hash256_parts(&[
            &digest,
            &(name.len() as u64).to_be_bytes(),
            name.as_bytes(),
            &(data.len() as u64).to_be_bytes(),
            &data,
        ]);
    }
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}
