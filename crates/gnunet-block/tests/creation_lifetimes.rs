//! Actual positive/negative compiler witnesses for retained per-group inputs.
use std::{
    error::Error,
    fs,
    path::Path,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};
fn cargo(root: &Path, operation: &str, locked: bool) -> Result<Output, Box<dyn Error>> {
    let mut command = Command::new("cargo");
    command
        .args([operation, "--manifest-path"])
        .arg(root.join("Cargo.toml"))
        .args(["--offline", "-j2", "--target-dir"])
        .arg(root.join("target"));
    if locked {
        command.arg("--locked");
    }
    Ok(command.output()?)
}
#[test]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Compiler status and diagnostic assertions accompany fallible private fixture construction"
)]
fn borrowed_creation_retains_two_distinct_tags_and_rejects_each_early_owner_drop()
-> Result<(), Box<dyn Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root = std::env::temp_dir().join(format!(
        "gnunet-block-creation-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root)?;
    fs::create_dir(root.join("src"))?;
    let package = Path::new(env!("CARGO_MANIFEST_DIR"));
    // gnunet-types is re-exported as Error through the block crate below; only one
    // path dependency is needed, preserving the actual production package identity.
    let escaped = package
        .to_str()
        .ok_or("package path encoding")?
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    fs::write(
        root.join("Cargo.toml"),
        format!(
            "[package]\nname=\"block-borrow-lifetime\"\nversion=\"0.0.0\"\nedition=\"2024\"\n[workspace]\n[dependencies]\ngnunet-block={{path=\"{escaped}\"}}\n"
        ),
    )?;
    let fixture = include_str!("ui/borrowed.rs").replace(
        "use gnunet_types::Error;",
        "use gnunet_block::ResourceError as Error;",
    );
    fs::write(root.join("src/main.rs"), &fixture)?;
    let built = cargo(&root, "build", false)?;
    fs::write(root.join("positive-build.stderr"), &built.stderr)?;
    assert!(
        built.status.success(),
        "positive borrowed groups must compile: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    let ran = Command::new(root.join(format!(
        "target/debug/block-borrow-lifetime{}",
        std::env::consts::EXE_SUFFIX
    )))
    .output()?;
    assert!(
        ran.status.success(),
        "two actual distinct group tags/callbacks must remain readable"
    );
    for (name, drop_owner) in [
        ("tag", "drop(tag1);"),
        ("context", "drop(context);"),
        ("storage", "drop(storage1);"),
        ("raw", "drop(raw1);"),
    ] {
        let source = fixture.replace("// lifetime-failure-marker", drop_owner);
        fs::write(root.join("src/main.rs"), source)?;
        let rejected = cargo(&root, "check", true)?;
        fs::write(
            root.join(format!("negative-{name}.stderr")),
            &rejected.stderr,
        )?;
        assert!(
            !rejected.status.success(),
            "{name} owner must not be moved while group callbacks borrow it"
        );
        let diagnostic = String::from_utf8_lossy(&rejected.stderr);
        assert!(
            diagnostic.contains("error[E0505]"),
            "expected actual borrow error, got {diagnostic}"
        );
    }
    fs::remove_dir_all(&root)?;
    Ok(())
}
