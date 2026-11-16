//! Bounded HTTP policy and original native Basic-secret publication.
use crate::Failure;
use gnunet_config::Configuration;
use gnunet_native::filesystem::{
    Directory, FileIdentity,
    publication::{self, Cleanup, Destination},
    validate_private_file,
};
use gnunet_rest_host::http::{Authorization, Cors, Policy};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
};
use zeroize::Zeroizing;
const LOCAL: &[u8] = b"rest-rust";
pub(super) fn policy(
    c: &Configuration,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<Policy, Failure> {
    let credentials = c.get(b"rest", b"REST_ALLOW_CREDENTIALS").is_some_and(|v| {
        v.eq_ignore_ascii_case(b"true") || v.eq_ignore_ascii_case(b"yes") || v == b"1"
    });
    let echo_webext = c
        .get(b"rest", b"REST_ECHO_ORIGIN_WEBEXT")
        .map(|_| c.get_yesno(b"rest", b"REST_ECHO_ORIGIN_WEBEXT"))
        .transpose()?
        .unwrap_or(false);
    let cors = Cors::new(
        c.get(b"rest", b"REST_ALLOW_ORIGIN"),
        echo_webext,
        credentials,
        c.get(b"rest", b"REST_ALLOW_HEADERS"),
    )?;
    let enabled = c
        .get(b"rest", b"BASIC_AUTH_ENABLED")
        .map(|_| c.get_yesno(b"rest", b"BASIC_AUTH_ENABLED"))
        .transpose()?
        .unwrap_or(true);
    let authorization = if enabled {
        let path = c.get_filename(
            b"rest",
            b"BASIC_AUTH_SECRET_FILE",
            &gnunet_config::ProcessEnvironment,
        )?;
        let file = secret_file(&path, reports)?;
        validate_private_file(&file)?;
        let metadata = file.metadata()?;
        if metadata.len() == 0 || metadata.len() > 4096 {
            return Err("REST Basic secret must contain 1..4096 bytes".into());
        }
        let mut secret = Zeroizing::new(Vec::new());
        secret.try_reserve_exact(4097)?;
        file.take(4097).read_to_end(&mut secret)?;
        if secret.len() != usize::try_from(metadata.len())? {
            return Err("REST Basic secret changed while reading".into());
        }
        let username = match c.get(LOCAL, b"BASIC_AUTH_USERNAME") {
            Some(name) => name.to_vec(),
            None => native_username()?,
        };
        Authorization::basic(&username, &secret)?
    } else {
        Authorization::disabled()
    };
    Ok(Policy {
        authorization,
        cors,
    })
}

#[cfg(unix)]
fn native_username() -> Result<Vec<u8>, Failure> {
    Ok(uzers::get_user_by_uid(nix::unistd::geteuid().as_raw())
        .ok_or("effective REST username unavailable")?
        .name()
        .as_encoded_bytes()
        .to_vec())
}
#[cfg(windows)]
fn native_username() -> Result<Vec<u8>, Failure> {
    Ok(gnunet_native::identity::process_account_name()?
        .into_string()
        .map_err(|_| "REST account name is not valid Unicode")?
        .into_bytes())
}
fn secret_file(
    path: &Path,
    reports: &gnunet_program_host::reporting::Reporter,
) -> Result<File, Failure> {
    if !path.is_absolute() {
        return Err("Basic secret path must be absolute".into());
    }
    let parent = path.parent().ok_or("Basic secret path lacks parent")?;
    let name = path.file_name().ok_or("Basic secret path lacks filename")?;
    let directory = Directory::open(parent)?;
    match directory.open_file(name) {
        Ok(file) => return Ok(file),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    directory.validate_namespace()?;
    let mut random = Zeroizing::new([0_u8; 32]);
    getrandom::fill(&mut *random)?;
    let mut password = Zeroizing::new([0_u8; 52]);
    let length = gnunet_rest::text::encode(&*random, &mut *password)?;
    let fence = || -> io::Result<()> {
        let selected = Directory::open(parent)?;
        selected.validate_namespace()?;
        if FileIdentity::of(selected.as_file())? != FileIdentity::of(directory.as_file())? {
            return Err(io::Error::other("original Basic secret namespace changed"));
        }
        Ok(())
    };
    match publication::publish(
        &directory,
        name,
        &password[..length],
        Destination::Create,
        fence,
    ) {
        Ok(published) => {
            let (original, barrier) = published.into_parts();
            fence()?;
            if !directory.same_file(name, &original)? {
                return Err("original Basic secret publication changed".into());
            }
            reports.debug(
                "rest.auth.publication",
                format_args!("Basic secret directory observation: {barrier:?}"),
            );
            Ok(original)
        }
        Err(error)
            if error.stage == "publish-create"
                && error.cause.kind() == io::ErrorKind::AlreadyExists
                && matches!(error.cleanup, Cleanup::Retired) =>
        {
            fence()?;
            Ok(directory.open_file(name)?)
        }
        Err(error) => Err(Box::new(error)),
    }
}
