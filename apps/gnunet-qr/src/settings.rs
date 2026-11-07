use crate::Failure;
use gnunet_config::Configuration;
use gnunet_program_host::{
    getopt::Options,
    helpers::{self, Target},
};
use gnunet_qr_host::Limits;
use std::{ffi::OsString, os::unix::ffi::OsStringExt, path::PathBuf, time::Duration};
pub(super) struct Arguments {
    png: Target<Option<Vec<u8>>>,
    device: Target<Option<Vec<u8>>>,
    no_display: Target<i32>,
    timeout: Target<u64>,
}
impl Arguments {
    pub fn new() -> Self {
        Self {
            png: Target::new(None),
            device: Target::new(None),
            no_display: Target::new(0),
            timeout: Target::new(0),
        }
    }
    pub fn options(&self) -> Options<'static> {
        let mut o = Options::new();
        o.add(helpers::string(
            b'p',
            b"png",
            b"FILE",
            b"Read one bounded PNG image instead of opening a camera",
            self.png.clone(),
        ));
        o.add(helpers::string(
            b'd',
            b"device",
            b"DEVICE",
            b"Explicit actual ZBar camera device (default /dev/video0)",
            self.device.clone(),
        ));
        o.add(helpers::flag(
            0,
            b"no-display",
            b"Do not request a native camera display window",
            self.no_display.clone(),
        ));
        o.add(helpers::relative_time(
            0,
            b"timeout",
            b"DURATION",
            b"Finite original scan plus URI handler whole lifetime",
            self.timeout.clone(),
        ));
        o
    }
    pub fn select(&self, c: &Configuration, remaining: &[Vec<u8>]) -> Result<Settings, Failure> {
        if !remaining.is_empty() {
            return Err("QR accepts --png FILE or --device DEVICE, not a predecoded URI positional argument".into());
        }
        let section = b"qr-rust";
        let num = |k: &[u8], d: u64| -> Result<u64, Failure> {
            Ok(c.get(section, k)
                .map(|_| c.get_number(section, k))
                .transpose()?
                .unwrap_or(d))
        };
        let size = |k: &[u8], d: usize| -> Result<usize, Failure> {
            Ok(usize::try_from(
                c.get(section, k)
                    .map(|_| c.get_size(section, k))
                    .transpose()?
                    .unwrap_or(u64::try_from(d)?),
            )?)
        };
        let defaults = Limits::default();
        let limits = Limits {
            encoded_bytes: size(b"INPUT_BYTES", defaults.encoded_bytes)?,
            width: u32::try_from(num(b"MAX_WIDTH", u64::from(defaults.width))?)?,
            height: u32::try_from(num(b"MAX_HEIGHT", u64::from(defaults.height))?)?,
            pixels: size(b"MAX_PIXELS", defaults.pixels)?,
            symbol_bytes: size(b"SYMBOL_BYTES", defaults.symbol_bytes)?,
            camera_poll_ms: u32::try_from(num(
                b"CAMERA_POLL_MS",
                u64::from(defaults.camera_poll_ms),
            )?)?,
            camera_width: u32::try_from(num(b"CAMERA_WIDTH", u64::from(defaults.camera_width))?)?,
            camera_height: u32::try_from(num(
                b"CAMERA_HEIGHT",
                u64::from(defaults.camera_height),
            )?)?,
        };
        limits.validate()?;
        let png = self
            .png
            .with(|v| v.as_deref().map(|v| owned(v, 4096)).transpose())??;
        let explicit = self
            .device
            .with(|v| v.as_deref().map(|v| owned(v, 4096)).transpose())??;
        if png.is_some() && explicit.is_some() {
            return Err("select either PNG input or a camera device".into());
        }
        let input = match png {
            Some(bytes) => Input::Png(PathBuf::from(OsString::from_vec(bytes))),
            None => Input::Camera(match explicit {
                Some(device) => device,
                None => owned(c.get(section, b"DEVICE").unwrap_or(b"/dev/video0"), 4096)?,
            }),
        };
        let us = self.timeout.get()?;
        let us = if us == 0 {
            c.get(section, b"TOTAL_TIMEOUT")
                .map(|_| c.get_time(section, b"TOTAL_TIMEOUT"))
                .transpose()?
                .unwrap_or(300_000_000)
        } else {
            us
        };
        if us == 0 || us > 86_400_000_000 {
            return Err("QR total timeout must be finite and at most one day".into());
        }
        let life = Duration::from_micros(us);
        if std::time::Instant::now().checked_add(life).is_none() {
            return Err("QR native whole target overflow".into());
        }
        let display = self.no_display.get()? == 0
            && c.get(section, b"DISPLAY")
                .map(|_| c.get_yesno(section, b"DISPLAY"))
                .transpose()?
                .unwrap_or(true);
        Ok(Settings {
            input,
            limits,
            life,
            display,
        })
    }
}
fn owned(bytes: &[u8], max: usize) -> Result<Vec<u8>, Failure> {
    if bytes.is_empty() || bytes.len() > max || bytes.contains(&0) {
        return Err("invalid or over-budget native input name".into());
    }
    let mut out = Vec::new();
    out.try_reserve_exact(bytes.len())?;
    if out.capacity() > max {
        return Err("native name allocation exceeds profile".into());
    }
    out.extend_from_slice(bytes);
    Ok(out)
}
pub(super) enum Input {
    Png(PathBuf),
    Camera(Vec<u8>),
}
pub(super) struct Settings {
    pub input: Input,
    pub limits: Limits,
    pub life: Duration,
    pub display: bool,
}
