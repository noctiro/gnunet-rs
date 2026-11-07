//! DNS trait adapter with exclusive reusable caller scratch.
use crate::{Error, Limits, NativeProfile, Workspace};
use core::cell::RefCell;
/// Complete native DNS text backend, borrowing its caller-owned scratch.
///
/// The explicit profile names both fixed lookup tables and runtime properties.
/// Independent concurrent users need independent workspaces. Reentrant use
/// returns Unavailable without claiming conversion or permitting raw fallback.
///
/// ```compile_fail,E0499
/// use gnunet_idna::{Backend,Limits,NativeProfile,Workspace};
/// use gnunet_dns::Idna;
/// let mut work=Workspace::new();
/// let backend=Backend::new(&mut work,Limits::GNUNET,NativeProfile::Libunistring1_5Unicode18_0);
/// let second=Backend::new(&mut work,Limits::GNUNET,NativeProfile::Unicode15_1);
/// backend.to_ascii(b"example",&mut [0;255]).unwrap();
/// second.to_ascii(b"example",&mut [0;255]).unwrap();
/// ```
///
/// Ending the adapter borrow allows the same scratch to be reused:
///
/// ```
/// use gnunet_idna::{Backend,Limits,NativeProfile,Workspace};
/// use gnunet_dns::Idna;
/// let mut work=Workspace::new();
/// {
///     let backend=Backend::new(&mut work,Limits::GNUNET,NativeProfile::Libunistring1_5Unicode18_0);
///     let mut out=[0;255];
///     assert_eq!(backend.to_ascii("faß.de".as_bytes(),&mut out),Ok(13));
///     assert_eq!(&out[..13],b"xn--fa-hia.de");
/// }
/// let second=Backend::new(&mut work,Limits::GNUNET,NativeProfile::Unicode15_1);
/// assert!(second.to_ascii(b"example",&mut [0;255]).is_ok());
/// ```
pub struct Backend<'a> {
    work: RefCell<&'a mut Workspace>,
    limits: Limits,
    profile: NativeProfile,
}
impl<'a> Backend<'a> {
    /// Bind one explicit native profile, input bound and exclusive caller scratch.
    pub const fn new(work: &'a mut Workspace, limits: Limits, profile: NativeProfile) -> Self {
        Self {
            work: RefCell::new(work),
            limits,
            profile,
        }
    }
}
fn convert_error(e: Error) -> gnunet_dns::Error {
    match e {
        Error::Capacity => gnunet_dns::Error::Capacity,
        Error::Resource => gnunet_dns::Error::TooLarge,
        Error::InteriorNul => gnunet_dns::Error::InvalidInput,
        Error::Native(_) => gnunet_dns::Error::Malformed,
    }
}
impl gnunet_dns::Idna for Backend<'_> {
    fn to_ascii(&self, input: &[u8], output: &mut [u8]) -> Result<usize, gnunet_dns::Error> {
        let mut work = self
            .work
            .try_borrow_mut()
            .map_err(|_| gnunet_dns::Error::Unavailable)?;
        crate::to_ascii(input, output, &mut work, self.limits, self.profile).map_err(convert_error)
    }
    fn to_unicode_label(
        &self,
        input: &[u8],
        output: &mut [u8],
    ) -> Result<usize, gnunet_dns::Error> {
        let mut work = self
            .work
            .try_borrow_mut()
            .map_err(|_| gnunet_dns::Error::Unavailable)?;
        crate::to_unicode(input, output, &mut work, self.limits).map_err(convert_error)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_dns::Idna;
    #[test]
    fn unavailable_workspace_never_reports_conversion_or_malformed() {
        let mut work = Workspace::new();
        let backend = Backend::new(
            &mut work,
            Limits::GNUNET,
            NativeProfile::Libunistring1_5Unicode18_0,
        );
        let _held = backend.work.borrow_mut();
        let mut out = [0xa5; 255];
        assert_eq!(
            backend.to_ascii(b"example", &mut out),
            Err(gnunet_dns::Error::Unavailable)
        );
        assert_eq!(
            backend.to_unicode_label(b"xn--e28h", &mut out),
            Err(gnunet_dns::Error::Unavailable)
        );
        assert_eq!(out, [0xa5; 255]);
    }
}
