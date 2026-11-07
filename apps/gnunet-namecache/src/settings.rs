use crate::Cause;
use gnunet_gnsrecord::ZoneKey;
use gnunet_gnsrecord_text::Profile;
use gnunet_program_host::helpers::Filename;
use std::{path::PathBuf, time::Duration};

pub(super) struct Settings {
    pub zone: ZoneKey,
    pub name: String,
    pub delete: bool,
    pub timeout: Duration,
    pub socket: Option<PathBuf>,
    pub profile: Profile,
}
impl Settings {
    pub fn new(
        zone: Option<Vec<u8>>,
        name: Option<Vec<u8>>,
        delete: bool,
        timeout: u32,
        socket: Filename,
        profile: Option<Vec<u8>>,
    ) -> Result<Self, Cause> {
        let zone = zone.ok_or("specify a public zone with -z/--zone")?;
        let zone = ZoneKey::from_ztld(std::str::from_utf8(&zone)?)?;
        let name = name.ok_or("specify a name with -n/--name")?;
        if name.is_empty() || name.len() > 1024 || name.contains(&0) {
            return Err("name must be nonempty UTF-8 without NUL, at most 1024 input bytes".into());
        }
        let name = String::from_utf8(name)?;
        if timeout == 0 || timeout > 3_600_000 {
            return Err("timeout must be 1..=3600000 milliseconds".into());
        }
        if let Some(error) = socket.error {
            return Err(format!("NAMECACHE endpoint filename: {error}").into());
        }
        let profile = match profile.as_deref() {
            None | Some(b"native") => Profile::NATIVE_255,
            Some(b"little") => Profile::LITTLE_255,
            Some(b"big") => Profile::BIG_255,
            _ => return Err("record-profile must be native, little or big".into()),
        };
        Ok(Self {
            zone,
            name,
            delete,
            timeout: Duration::from_millis(u64::from(timeout)),
            socket: socket.path,
            profile,
        })
    }
}
