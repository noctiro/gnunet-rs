use super::Settings;
use gnunet_config::{Configuration, ProjectData};
use std::{error::Error, sync::Arc};

fn configured() -> Result<Configuration, Box<dyn Error>> {
    let mut config = Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
    config.set_value(b"uri", b"gns", Some(b"gnunet-namestore -e 1a -u"))?;
    Ok(config)
}

#[test]
fn qr_uses_config_arguments_and_keeps_decoded_uri_one_argument() -> Result<(), Box<dyn Error>> {
    let config = configured()?;
    #[cfg(unix)]
    let uri = b"GnUnEt://gns/original payload%20\xff";
    #[cfg(windows)]
    let uri = b"GnUnEt://gns/original payload%20\xe6\x97\xa5";
    let selected = Settings::from_qr_uri(&config, uri)?;
    assert!(gnunet_native::os_bytes::encode(&selected.handler).as_ref() == b"gnunet-namestore");
    assert!(
        selected
            .arguments
            .iter()
            .map(|a| gnunet_native::os_bytes::encode(a).into_owned())
            .collect::<Vec<_>>()
            == [b"-e".as_slice(), b"1a", b"-u"]
    );
    assert!(gnunet_native::os_bytes::encode(&selected.uri).as_ref() == uri);
    assert!(selected.inherit_stdio);
    Ok(())
}

#[test]
fn ordinary_uri_uses_same_configured_arguments_and_rejects_nul() -> Result<(), Box<dyn Error>> {
    let config = configured()?;
    let selected = Settings::from_uri(&config, b"gnunet://gns/original")?;
    assert!(gnunet_native::os_bytes::encode(&selected.handler).as_ref() == b"gnunet-namestore");
    assert!(
        selected
            .arguments
            .last()
            .is_some_and(|a| gnunet_native::os_bytes::encode(a).as_ref() == b"-u")
    );
    assert!(gnunet_native::os_bytes::encode(&selected.uri).as_ref() == b"gnunet://gns/original");
    assert!(!selected.inherit_stdio);
    assert!(Settings::from_qr_uri(&config, b"gnunet://gns/one\0two").is_err());
    Ok(())
}
