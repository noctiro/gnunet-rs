use super::Settings;
use gnunet_config::{Configuration, ProjectData};
use std::{error::Error, os::unix::ffi::OsStrExt, sync::Arc};

fn configured() -> Result<Configuration, Box<dyn Error>> {
    let mut config = Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
    config.set_value(b"uri", b"gns", Some(b"gnunet-namestore -e 1a -u"))?;
    Ok(config)
}

#[test]
fn qr_uses_config_arguments_and_keeps_decoded_uri_one_argument() -> Result<(), Box<dyn Error>> {
    let config = configured()?;
    let uri = b"GnUnEt://gns/original payload%20\xff";
    let selected = Settings::from_qr_uri(&config, uri)?;
    assert!(selected.handler.as_bytes() == b"gnunet-namestore");
    assert!(
        selected
            .arguments
            .iter()
            .map(|a| a.as_bytes())
            .collect::<Vec<_>>()
            == [b"-e".as_slice(), b"1a", b"-u"]
    );
    assert!(selected.uri.as_bytes() == uri);
    assert!(selected.inherit_stdio);
    Ok(())
}

#[test]
fn ordinary_uri_uses_same_configured_arguments_and_rejects_nul() -> Result<(), Box<dyn Error>> {
    let config = configured()?;
    let selected = Settings::from_uri(&config, b"gnunet://gns/original")?;
    assert!(selected.handler.as_bytes() == b"gnunet-namestore");
    assert!(
        selected
            .arguments
            .last()
            .is_some_and(|a| a.as_bytes() == b"-u")
    );
    assert!(selected.uri.as_bytes() == b"gnunet://gns/original");
    assert!(!selected.inherit_stdio);
    assert!(Settings::from_qr_uri(&config, b"gnunet://gns/one\0two").is_err());
    Ok(())
}
