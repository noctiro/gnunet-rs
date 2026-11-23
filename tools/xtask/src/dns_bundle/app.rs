//! Assemble a containing application and its exact bundled DNS provider.
use super::{Metadata, binary, provider, write_new};
use std::{error::Error, fs, io::Write, path::PathBuf};

const INFO: &str =
    include_str!("../../../../apps/gnunet-service-dns/macos/Application-Info.plist.in");
const ENTITLEMENTS: &str =
    include_str!("../../../../apps/gnunet-service-dns/macos/Application.entitlements.in");

pub(crate) fn bundle(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let mut control = None;
    let mut extension = None;
    let mut output = None;
    let mut identifier = None;
    let mut provider_id = None;
    let mut group = None;
    let mut version = None;
    for pair in arguments.chunks(2) {
        if pair.len() != 2 {
            return Err("bundle-dns-app requires option/value pairs".into());
        }
        match pair[0].as_str() {
            "--control-binary" if control.is_none() => control = Some(PathBuf::from(&pair[1])),
            "--provider-binary" if extension.is_none() => extension = Some(PathBuf::from(&pair[1])),
            "--output" if output.is_none() => output = Some(PathBuf::from(&pair[1])),
            "--bundle-id" if identifier.is_none() => identifier = Some(pair[1].clone()),
            "--provider-id" if provider_id.is_none() => provider_id = Some(pair[1].clone()),
            "--app-group" if group.is_none() => group = Some(pair[1].clone()),
            "--version" if version.is_none() => version = Some(pair[1].clone()),
            _ => return Err("unknown or duplicate bundle-dns-app option".into()),
        }
    }
    let control = control.ok_or("--control-binary is required")?;
    let extension = extension.ok_or("--provider-binary is required")?;
    let output = output.ok_or("--output is required")?;
    let identifier = identifier.ok_or("--bundle-id is required")?;
    let provider_id = provider_id.ok_or("--provider-id is required")?;
    let group = group.ok_or("--app-group is required")?;
    let version = version.unwrap_or_else(|| "1.0.0".to_owned());
    let app = Metadata::new(&identifier, &group, &version)?;
    let extension_metadata = Metadata::new(&provider_id, &group, &version)?;
    if !provider_id.starts_with(&format!("{identifier}.")) {
        return Err("--provider-id must be a child of --bundle-id".into());
    }
    if output.extension().and_then(|value| value.to_str()) != Some("app") {
        return Err("--output must name a new .app bundle".into());
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    // Every created artifact is exclusive. An incomplete build is retained for
    // inspection, with no recursive cleanup or overwrite of another package.
    fs::create_dir(&output)?;
    let contents = output.join("Contents");
    let executables = contents.join("MacOS");
    fs::create_dir_all(&executables)?;
    binary::copy(&control, &executables.join("gnunet-dns-control"))?;
    let embedded = contents.join("Library/SystemExtensions");
    fs::create_dir_all(&embedded)?;
    provider(
        &extension,
        &embedded.join(format!("{provider_id}.systemextension")),
        &extension_metadata,
    )?;
    write_new(
        &contents.join("Info.plist"),
        INFO.replace("@BUNDLE_ID@", app.identifier)
            .replace("@BUNDLE_VERSION@", app.version)
            .replace("@PROVIDER_ID@", &provider_id)
            .as_bytes(),
    )?;
    let app_entitlements = output.with_extension("entitlements");
    write_new(
        &app_entitlements,
        ENTITLEMENTS.replace("@APP_GROUP@", &group).as_bytes(),
    )?;
    let provider_entitlements = output.with_extension("provider.entitlements");
    write_new(
        &provider_entitlements,
        extension_metadata.entitlements().as_bytes(),
    )?;
    writeln!(
        std::io::stdout().lock(),
        "Unsigned DNS containing application: {}\nApplication signing input: {}\nProvider signing input: {}",
        output.display(),
        app_entitlements.display(),
        provider_entitlements.display(),
    )?;
    Ok(())
}
