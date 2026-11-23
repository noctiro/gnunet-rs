//! Bind and stage the original externally prepared WFP driver package.
mod catalog;

use super::{Platform, Result, Target};
use gnunet_crypto::Hash512State;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::Path,
};

const INF: &str =
    include_str!("../../../../platform/windows/wfp-driver/package/gnunet-wfp-driver.inf.in");
const STAGED: &str = "share/gnunet/providers/windows/wfp";
const DRIVER: &str = "gnunet-wfp-driver.sys";
const INSTRUCTIONS: &str = "gnunet-wfp-driver.inf";
const CATALOG: &str = "gnunet-wfp-driver.cat";

struct Architecture {
    machine: u16,
    inf: &'static str,
}

impl Architecture {
    fn of(target: &Target) -> Result<Self> {
        if target.platform() != Platform::Windows {
            return Err("--wfp-package requires a Windows node target".into());
        }
        match target.triple.split_once('-').map(|(arch, _)| arch) {
            Some("x86_64") => Ok(Self {
                machine: 0x8664,
                inf: "amd64",
            }),
            Some("aarch64") => Ok(Self {
                machine: 0xaa64,
                inf: "arm64",
            }),
            _ => Err("--wfp-package requires an x64 or ARM64 Windows target".into()),
        }
    }
}

pub(super) struct Package {
    architecture: Architecture,
    image: Source,
    inf: Source,
    catalog: Source,
}

impl Package {
    pub(super) fn open(path: &Path, target: &Target) -> Result<Self> {
        let architecture = Architecture::of(target)?;
        if !fs::symlink_metadata(path)?.is_dir() {
            return Err("--wfp-package requires an ordinary package directory".into());
        }
        let mut image = Source::open(path, DRIVER, 32 * 1024 * 1024)?;
        let mut inf = Source::open(path, INSTRUCTIONS, 64 * 1024)?;
        let mut catalog = Source::open(path, CATALOG, 16 * 1024 * 1024)?;
        pe_image(&mut image.file, &architecture, image.bytes)?;
        inf_file(&mut inf.file, &architecture, inf.bytes)?;
        catalog::signed_data(&mut catalog.file, catalog.bytes)?;
        Ok(Self {
            architecture,
            image,
            inf,
            catalog,
        })
    }

    pub(super) fn stage(mut self, prefix: &Path) -> Result<()> {
        let destination = prefix.join(STAGED);
        fs::create_dir_all(&destination)?;
        let mut image = self.image.stage(&destination.join(DRIVER))?;
        let mut inf = self.inf.stage(&destination.join(INSTRUCTIONS))?;
        let mut catalog = self.catalog.stage(&destination.join(CATALOG))?;
        pe_image(&mut image, &self.architecture, self.image.bytes)?;
        inf_file(&mut inf, &self.architecture, self.inf.bytes)?;
        catalog::signed_data(&mut catalog, self.catalog.bytes)?;
        Ok(())
    }
}

struct Source {
    file: File,
    bytes: u64,
    fingerprint: [u8; 64],
}

impl Source {
    fn open(path: &Path, name: &str, maximum: u64) -> Result<Self> {
        let path = path.join(name);
        let observed = fs::symlink_metadata(&path)?;
        if !observed.is_file() || !(1..=maximum).contains(&observed.len()) {
            return Err(format!("invalid WFP package file {}", path.display()).into());
        }
        let mut file = File::open(&path)?;
        let metadata = file.metadata()?;
        let bytes = metadata.len();
        if !metadata.is_file() || bytes != observed.len() {
            return Err(
                format!("WFP package file changed while opening {}", path.display()).into(),
            );
        }
        let fingerprint = read_exact_content(&mut file, bytes, io::sink())?;
        Ok(Self {
            file,
            bytes,
            fingerprint,
        })
    }

    fn stage(&mut self, destination: &Path) -> Result<File> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(destination)?;
        let fingerprint = read_exact_content(&mut self.file, self.bytes, &mut file)?;
        if fingerprint != self.fingerprint {
            return Err(format!(
                "WFP package file changed before staging {}",
                destination.display()
            )
            .into());
        }
        file.flush()?;
        Ok(file)
    }
}

fn read_exact_content(source: &mut File, bytes: u64, mut sink: impl Write) -> io::Result<[u8; 64]> {
    source.rewind()?;
    let mut hash = Hash512State::new();
    let mut input = source.take(bytes + 1);
    let mut remaining = bytes;
    let mut buffer = [0; 16 * 1024];
    loop {
        let n = input.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        remaining = remaining
            .checked_sub(n as u64)
            .ok_or_else(|| io::Error::other("WFP package file grew while reading"))?;
        hash.update(&buffer[..n]);
        sink.write_all(&buffer[..n])?;
    }
    if remaining != 0 {
        return Err(io::Error::other("WFP package file shrank while reading"));
    }
    Ok(hash.finish())
}

fn pe_image(file: &mut File, architecture: &Architecture, bytes: u64) -> Result<()> {
    file.rewind()?;
    let mut dos = [0u8; 64];
    file.read_exact(&mut dos)?;
    let offset = u64::from(u32::from_le_bytes(dos[60..64].try_into()?));
    let invalid = "WFP package image must be a PE32+ native executable matching the Windows node architecture";
    if &dos[..2] != b"MZ" || offset < dos.len() as u64 || offset + 136 > bytes {
        return Err(invalid.into());
    }
    file.seek(SeekFrom::Start(offset))?;
    let mut header = [0u8; 136];
    file.read_exact(&mut header)?;
    let word = |offset| u16::from_le_bytes([header[offset], header[offset + 1]]);
    let optional = u64::from(word(20));
    if &header[..4] != b"PE\0\0"
        || word(4) != architecture.machine
        || word(6) == 0
        || word(22) & 2 == 0
        || optional < 112
        || offset + 24 + optional > bytes
        || word(24) != 0x020b
        || header[40..44] == [0; 4]
        || word(92) != 1
    {
        return Err(invalid.into());
    }
    Ok(())
}

fn inf_file(file: &mut File, architecture: &Architecture, bytes: u64) -> Result<()> {
    file.rewind()?;
    let expected = INF.replace("@ARCH@", architecture.inf);
    let mut actual = String::new();
    file.take(bytes).read_to_string(&mut actual)?;
    if !actual
        .trim_start_matches('\u{feff}')
        .lines()
        .eq(expected.lines())
    {
        return Err(
            "WFP package INF does not match the generated driver INF for this Windows target"
                .into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _removed = fs::remove_dir_all(&self.0);
        }
    }

    fn field(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![tag, body.len() as u8];
        bytes.extend_from_slice(body);
        bytes
    }

    fn catalog_fixture() -> Vec<u8> {
        let id = field(2, &[1]);
        let oid = field(6, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 2]);
        let algorithm = field(0x30, &oid);
        let signer = field(
            0x30,
            &[
                id.clone(),
                field(0x80, &[1]),
                algorithm.clone(),
                algorithm.clone(),
                field(4, &[42]),
            ]
            .concat(),
        );
        let signed = field(
            0x30,
            &[
                id,
                field(0x31, &algorithm),
                field(0x30, &oid),
                field(0x31, &signer),
            ]
            .concat(),
        );
        field(0x30, &[oid, field(0xa0, &signed)].concat())
    }

    fn image_fixture() -> Vec<u8> {
        let mut bytes = vec![0; 200];
        bytes[..2].copy_from_slice(b"MZ");
        bytes[60..64].copy_from_slice(&64u32.to_le_bytes());
        let header = &mut bytes[64..];
        header[..4].copy_from_slice(b"PE\0\0");
        for (offset, word) in [
            (4, 0x8664u16),
            (6, 1),
            (20, 112),
            (22, 2),
            (24, 0x020b),
            (92, 1),
        ] {
            header[offset..offset + 2].copy_from_slice(&word.to_le_bytes());
        }
        header[40] = 1;
        bytes
    }

    #[test]
    fn wfp_staging_matches_target_and_preserves_package_bytes() -> Result<()> {
        let stamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let scratch = Scratch(
            std::env::temp_dir().join(format!("gn-wfp-stage-{}-{stamp}", std::process::id())),
        );
        fs::create_dir(&scratch.0)?;
        let source = scratch.0.join("source");
        fs::create_dir(&source)?;
        let files = [
            (DRIVER, image_fixture()),
            (INSTRUCTIONS, INF.replace("@ARCH@", "amd64").into_bytes()),
            (CATALOG, catalog_fixture()),
        ];
        for (name, bytes) in &files {
            fs::write(source.join(name), bytes)?;
        }
        let target = Target::from_cfg("x86_64-pc-windows-msvc".into(), "target_os=\"windows\"")?;
        let wrong = Target::from_cfg("aarch64-pc-windows-msvc".into(), "target_os=\"windows\"")?;
        if Package::open(&source, &wrong).is_ok() {
            return Err("staging accepted a driver for another architecture".into());
        }
        let output = scratch.0.join("prefix");
        Package::open(&source, &target)?.stage(&output)?;
        for (name, bytes) in files {
            if fs::read(output.join(STAGED).join(name))? != bytes {
                return Err("staging changed an original package file".into());
            }
        }
        Ok(())
    }
}
