use crate::{Result, allowlist, cli::Inputs, command, includes, invalid, receipt, sdk};
use serde_json::json;
use std::{
    env,
    ffi::OsStr,
    fs,
    path::Path,
    process::{Command, Output},
};

const HEADER: &str = include_str!("../sdk/wrapper.h");
const WRAPPERS: &str = include_str!("../sdk/wrappers.c");

fn clang(inputs: &Inputs, step: &str, args: &[String]) -> Result<Output> {
    command::run(&inputs.output, step, Command::new(&inputs.clang).args(args))
}

fn clean_environment() -> Result<()> {
    for (name, _) in env::vars_os() {
        let text = name.to_string_lossy();
        if text.starts_with("BINDGEN_EXTRA_CLANG_ARGS")
            || [
                "SDKROOT",
                "CPATH",
                "C_INCLUDE_PATH",
                "CPLUS_INCLUDE_PATH",
                "OBJC_INCLUDE_PATH",
            ]
            .iter()
            .any(|candidate| name == OsStr::new(candidate))
        {
            return Err(invalid(format!(
                "remove ambient {text}; include and target inputs are explicit"
            ))
            .into());
        }
    }
    Ok(())
}

pub fn run(inputs: &Inputs) -> Result<()> {
    clean_environment()?;
    let target = inputs.target;
    let mut source_inputs = target.validate(&inputs.sdk)?;
    let version = clang(inputs, "clang-version", &["--version".into()])?;
    let version = String::from_utf8(version.stdout)?;
    if !version.contains("clang version 21.") {
        return Err(invalid("this checked profile requires Clang 21").into());
    }
    let library = bindgen::clang_version();
    if !library.parsed.is_some_and(|(major, _)| major == 21) {
        return Err(invalid("this checked profile requires libclang 21").into());
    }
    let resource = clang(inputs, "clang-resource", &["-print-resource-dir".into()])?;
    let resource = String::from_utf8(resource.stdout)?;
    let resource = Path::new(resource.trim()).join("include").canonicalize()?;
    if !resource.join("intrin.h").is_file() {
        return Err(invalid("actual Clang intrinsic headers were not found").into());
    }
    let paths = target.include_paths(&inputs.sdk);
    let overlay = inputs.output.join("sdk-includes.json");
    includes::write(&overlay, &paths)?;
    let mut args = Vec::from(target.clang_arch());
    args.extend(sdk::arguments(&paths, &resource, &overlay)?);
    fs::write(inputs.output.join("wrapper.h"), HEADER)?;
    fs::write(inputs.output.join("wrappers.c"), WRAPPERS)?;
    receipt::write(&inputs.output.join("clang-args.json"), &json!(args))?;
    let headers = receipt::Headers::default();
    let mut builder = bindgen::Builder::default()
        .header(sdk::utf8(&inputs.output.join("wrapper.h"))?)
        .clang_args(&args)
        .detect_include_paths(false)
        .use_core()
        .ctypes_prefix("core::ffi")
        .layout_tests(false)
        .derive_debug(false)
        .derive_default(false)
        .generate_comments(false)
        .rust_target(
            bindgen::RustTarget::stable(99, 1)
                .map_err(|error| invalid(format!("unsupported Rust output target: {error:?}")))?,
        )
        .rust_edition(bindgen::RustEdition::Edition2024)
        .wrap_unsafe_ops(true)
        .parse_callbacks(Box::new(headers.clone()));
    for pattern in allowlist::FUNCTIONS {
        builder = builder.allowlist_function(pattern);
    }
    for pattern in allowlist::TYPES {
        builder = builder.allowlist_type(pattern);
    }
    for pattern in allowlist::VARIABLES {
        builder = builder.allowlist_var(pattern);
    }
    let mut generated = Vec::new();
    builder.generate()?.write(Box::new(&mut generated))?;
    let text = std::str::from_utf8(&generated)?;
    for required in [
        "pub fn NdisGetDataBuffer(",
        "pub fn WdmlibIoCreateDeviceSecure(",
        "FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS",
        "FWPS_FIELD_DATAGRAM_DATA_V6_IP_LOCAL_ADDRESS",
        "FWPS_METADATA_FIELD_FLOW_HANDLE",
        "pub type FWPS_INCOMING_METADATA_VALUES0",
        "pub fn gnunet_wfp_nbl_first_nb(",
        "pub const GNUNET_WFP_STATUS_NOT_SUPPORTED",
        "pub const GNUNET_WFP_ABI_MACHINE",
        "pub const GNUNET_WFP_POOL_ALIGNMENT",
    ] {
        if !text.contains(required) {
            return Err(
                invalid(format!("real header generation did not provide {required}")).into(),
            );
        }
    }
    fs::write(inputs.output.join("bindings.rs"), generated)?;
    let mut compile_args = args;
    compile_args.extend(
        [
            "-ffreestanding",
            "-fno-stack-protector",
            "-mno-red-zone",
            "-c",
        ]
        .map(str::to_owned),
    );
    compile_args.extend([
        sdk::utf8(&inputs.output.join("wrappers.c"))?,
        "-o".into(),
        sdk::utf8(&inputs.output.join("wrappers.obj"))?,
    ]);
    clang(inputs, "compile-wrappers", &compile_args)?;
    source_inputs.extend(headers.files()?);
    source_inputs.sort();
    source_inputs.dedup();
    let files: Vec<_> = source_inputs
        .iter()
        .map(|path| receipt::file(path))
        .collect::<Result<_>>()?;
    let artifacts = [
        "wrapper.h",
        "wrappers.c",
        "wrappers.obj",
        "bindings.rs",
        "clang-args.json",
        "sdk-includes.json",
    ]
    .map(|name| receipt::file(&inputs.output.join(name)))
    .into_iter()
    .collect::<Result<Vec<_>>>()?;
    receipt::write(
        &inputs.output.join("receipt.json"),
        &json!({
            "status": "bindings-and-sdk-wrappers-built", "target": target.triple,
            "profile": target.profile, "package_version": sdk::PACKAGE_VERSION,
            "libclang": library.full, "clang": version.trim(),
            "libclang_path": env::var_os("LIBCLANG_PATH").map(|value| value.to_string_lossy().into_owned()),
            "scope": "SDK ABI generation and compile-only wrappers; no driver linking, registration or execution",
            "tool_sources": receipt::sources(), "input_files": files, "artifacts": artifacts,
        }),
    )?;
    println!(
        "Generated bindings and native SDK wrappers in {}",
        inputs.output.display()
    );
    Ok(())
}
