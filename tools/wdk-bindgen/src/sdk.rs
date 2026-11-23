use crate::{Result, invalid};
use std::{
    ffi::OsStr,
    fs,
    path::{Path, PathBuf},
};

pub const PACKAGE_VERSION: &str = "10.0.28000.2526";

/// One WDK target from header selection through final package inspection.
pub struct Target {
    pub triple: &'static str,
    pub profile: &'static str,
    pub linker_machine: &'static str,
    pub pe_machine: object::pe::Machine,
    pub pe_name: &'static str,
    pub inf_arch: &'static str,
    wdk: &'static str,
    sdk: &'static str,
    define: &'static str,
}

const X64: Target = Target {
    triple: "x86_64-pc-windows-msvc",
    profile: "win11-br-ndis630-msvc1944-x64",
    linker_machine: "x64",
    pe_machine: object::pe::IMAGE_FILE_MACHINE_AMD64,
    pe_name: "AMD64",
    inf_arch: "amd64",
    wdk: "Microsoft.Windows.WDK.x64",
    sdk: "Microsoft.Windows.SDK.CPP.x64",
    define: "-D_AMD64_=1",
};

const ARM64: Target = Target {
    triple: "aarch64-pc-windows-msvc",
    profile: "win11-br-ndis630-msvc1944-arm64",
    linker_machine: "arm64",
    pe_machine: object::pe::IMAGE_FILE_MACHINE_ARM64,
    pe_name: "ARM64",
    inf_arch: "arm64",
    wdk: "Microsoft.Windows.WDK.ARM64",
    sdk: "Microsoft.Windows.SDK.CPP.ARM64",
    define: "-D_ARM64_=1",
};

impl Target {
    pub fn parse(value: &OsStr) -> Result<&'static Self> {
        [&X64, &ARM64]
            .into_iter()
            .find(|target| value == target.triple)
            .ok_or_else(|| invalid(format!("unsupported WDK target: {value:?}")).into())
    }

    pub fn validate(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let mut inputs = Vec::new();
        for name in [self.wdk, "Microsoft.Windows.SDK.CPP", self.sdk] {
            let package = root.join(name.to_ascii_lowercase());
            let filename = format!("{name}.nuspec");
            let mut matches = Vec::new();
            for entry in fs::read_dir(&package)? {
                let entry = entry?;
                if entry
                    .file_name()
                    .as_encoded_bytes()
                    .eq_ignore_ascii_case(filename.as_bytes())
                {
                    matches.push(entry.path());
                }
            }
            let [path] = matches.as_slice() else {
                return Err(invalid(format!(
                    "expected one {filename} under {}",
                    package.display()
                ))
                .into());
            };
            let metadata = fs::read_to_string(path)?;
            let id = metadata
                .split_once("<id>")
                .and_then(|(_, value)| value.split_once("</id>"))
                .map(|(id, _)| id);
            if !id.is_some_and(|id| id.eq_ignore_ascii_case(name))
                || !metadata.contains(&format!("<version>{PACKAGE_VERSION}</version>"))
            {
                return Err(invalid(format!(
                    "SDK package metadata does not match fixed input: {}",
                    path.display()
                ))
                .into());
            }
            inputs.push(path.clone());
        }
        inputs.push(root.join(self.wdk.to_ascii_lowercase()).join("LICENSE.txt"));
        Ok(inputs)
    }

    pub fn include_paths(&self, root: &Path) -> [PathBuf; 5] {
        let wdk = root
            .join(self.wdk.to_ascii_lowercase())
            .join("c/Include/10.0.28000.0");
        let sdk = root.join("microsoft.windows.sdk.cpp/c/Include/10.0.28000.0");
        [
            wdk.join("km"),
            wdk.join("km/crt"),
            wdk.join("shared"),
            sdk.join("shared"),
            sdk.join("ucrt"),
        ]
    }

    pub fn driver_libraries(&self, root: &Path) -> [PathBuf; 8] {
        let kernel = root
            .join(self.wdk.to_ascii_lowercase())
            .join("c/Lib/10.0.28000.0/km")
            .join(self.linker_machine);
        [
            kernel.join("bufferoverflowfastfailk.lib"),
            kernel.join("ntoskrnl.lib"),
            kernel.join("hal.lib"),
            kernel.join("wmilib.lib"),
            kernel.join("fwpkclnt.lib"),
            kernel.join("ndis.lib"),
            kernel.join("wdmsec.lib"),
            root.join(self.sdk.to_ascii_lowercase())
                .join("c/um")
                .join(self.linker_machine)
                .join("Uuid.Lib"),
        ]
    }

    pub fn clang_arch(&self) -> [String; 2] {
        [format!("--target={}", self.triple), self.define.into()]
    }
}

pub fn arguments(paths: &[PathBuf], resource: &Path, overlay: &Path) -> Result<Vec<String>> {
    let mut args = vec![
        "-x".into(),
        "c".into(),
        "-std=c17".into(),
        "-fms-extensions".into(),
        "-fms-compatibility".into(),
        "-fms-compatibility-version=19.44".into(),
        "-nostdinc".into(),
        "-isystem".into(),
        utf8(resource)?,
        "-ivfsoverlay".into(),
        utf8(overlay)?,
    ];
    for path in paths {
        args.extend(["-I".into(), utf8(path)?]);
    }
    args.extend(
        [
            "-D_KERNEL_MODE=1",
            "-DNDIS630=1",
            "-DNTDDI_VERSION=0x0A000012",
            "-D_WIN32_WINNT=0x0A00",
            "-DWINVER=0x0A00",
        ]
        .map(str::to_owned),
    );
    Ok(args)
}

pub fn utf8(path: &Path) -> Result<String> {
    Ok(path
        .to_str()
        .ok_or_else(|| invalid("SDK/Clang path must be UTF-8 for libclang"))?
        .to_owned())
}
