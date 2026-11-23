//! Windows driver trust bound to members of the supplied catalog.
use super::package::{Member, Package, invalid};
use crate::NativeFailure;
use std::{
    io::{self, Seek},
    mem::size_of,
    os::windows::io::AsRawHandle,
    ptr,
};
use windows_sys::Win32::{
    Foundation::INVALID_HANDLE_VALUE,
    Security::{
        Cryptography::{
            BCRYPT_SHA256_ALGORITHM,
            Catalog::{
                CryptCATAdminAcquireContext2, CryptCATAdminCalcHashFromFileHandle2,
                CryptCATAdminReleaseContext,
            },
        },
        WinTrust::{
            DRIVER_ACTION_VERIFY, WINTRUST_CATALOG_INFO, WINTRUST_DATA, WINTRUST_DATA_0,
            WTD_CACHE_ONLY_URL_RETRIEVAL, WTD_CHOICE_CATALOG,
            WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN, WTD_STATEACTION_CLOSE,
            WTD_STATEACTION_VERIFY, WTD_UI_NONE, WinVerifyTrust,
        },
    },
};

pub(super) fn verify(package: &Package) -> io::Result<()> {
    let admin = Admin::open()?;
    let verified = admin
        .verify(&package.catalog, &package.inf)
        .and_then(|()| admin.verify(&package.catalog, &package.image));
    let closed = admin.close();
    match (verified, closed) {
        (Ok(()), result) | (result, Ok(())) => result,
        (Err(primary), Err(close)) => Err(io::Error::other(format!("{primary}. {close}"))),
    }
}

struct Admin(isize);

impl Admin {
    #[expect(
        unsafe_code,
        reason = "Catalog context acquisition returns one original owned native context"
    )]
    fn open() -> io::Result<Self> {
        let mut admin = 0;
        // SAFETY: output is one initialized HCATADMIN. Policy and algorithm are fixed.
        if unsafe {
            CryptCATAdminAcquireContext2(
                &mut admin,
                &DRIVER_ACTION_VERIFY,
                BCRYPT_SHA256_ALGORITHM,
                ptr::null(),
                0,
            )
        } == 0
        {
            return Err(last_error("CryptCATAdminAcquireContext2"));
        }
        if admin == 0 {
            return Err(invalid("Windows supplied no catalog administrator context"));
        }
        Ok(Self(admin))
    }

    #[expect(
        unsafe_code,
        reason = "Catalog hashing and verification borrow pinned exact members and initialized ABI records"
    )]
    fn verify(&self, catalog: &Member, member: &Member) -> io::Result<()> {
        (&member.file).rewind()?;
        let mut hash = [0; 32];
        let mut length = hash.len() as u32;
        // SAFETY: SHA-256 context and original read handle are live. The output extent is 32 bytes.
        if unsafe {
            CryptCATAdminCalcHashFromFileHandle2(
                self.0,
                member.file.as_raw_handle(),
                &mut length,
                hash.as_mut_ptr(),
                0,
            )
        } == 0
        {
            return Err(last_error("CryptCATAdminCalcHashFromFileHandle2"));
        }
        if length as usize != hash.len() {
            return Err(invalid("unexpected Windows catalog SHA-256 hash length"));
        }
        (&member.file).rewind()?;
        let mut tag = [0u16; 65];
        let hex = b"0123456789ABCDEF";
        for (index, byte) in hash.iter().copied().enumerate() {
            tag[2 * index] = u16::from(hex[usize::from(byte >> 4)]);
            tag[2 * index + 1] = u16::from(hex[usize::from(byte & 15)]);
        }
        let mut selection = WINTRUST_CATALOG_INFO {
            cbStruct: size_of::<WINTRUST_CATALOG_INFO>() as u32,
            pcwszCatalogFilePath: catalog.path.as_ptr(),
            pcwszMemberTag: tag.as_ptr(),
            pcwszMemberFilePath: member.path.as_ptr(),
            hMemberFile: member.file.as_raw_handle(),
            pbCalculatedFileHash: hash.as_mut_ptr(),
            cbCalculatedFileHash: length,
            hCatAdmin: self.0,
            ..WINTRUST_CATALOG_INFO::default()
        };
        let mut data = WINTRUST_DATA {
            cbStruct: size_of::<WINTRUST_DATA>() as u32,
            dwUIChoice: WTD_UI_NONE,
            fdwRevocationChecks: WTD_REVOKE_WHOLECHAIN,
            dwUnionChoice: WTD_CHOICE_CATALOG,
            Anonymous: WINTRUST_DATA_0 {
                pCatalog: &mut selection,
            },
            dwStateAction: WTD_STATEACTION_VERIFY,
            dwProvFlags: WTD_CACHE_ONLY_URL_RETRIEVAL | WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT,
            ..WINTRUST_DATA::default()
        };
        let mut action = DRIVER_ACTION_VERIFY;
        // SAFETY: all pointees and original path leases outlive verification and its native close.
        let verdict = unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            )
        };
        data.dwStateAction = WTD_STATEACTION_CLOSE;
        // SAFETY: close is required after every VERIFY and uses the same live inputs and state.
        let close = unsafe {
            WinVerifyTrust(
                INVALID_HANDLE_VALUE,
                &mut action,
                (&mut data as *mut WINTRUST_DATA).cast(),
            )
        };
        let operation = "WinVerifyTrust package member";
        match (verdict, close) {
            (0, 0) => Ok(()),
            (verdict, 0) => Err(native(operation, verdict)),
            (0, close) => Err(native("WinVerifyTrust close", close)),
            (verdict, close) => Err(io::Error::other(format!(
                "{operation} returned {verdict:#010x}. WinVerifyTrust close returned {close:#010x}"
            ))),
        }
    }

    #[expect(
        unsafe_code,
        reason = "Original catalog context is released exactly once"
    )]
    fn close(self) -> io::Result<()> {
        // SAFETY: this context is used only by the completed synchronous verification calls.
        if unsafe { CryptCATAdminReleaseContext(self.0, 0) } == 0 {
            return Err(last_error("CryptCATAdminReleaseContext"));
        }
        Ok(())
    }
}

pub(super) fn last_error(operation: &'static str) -> io::Error {
    let code = io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or_default();
    native(operation, code)
}

pub(super) fn native(operation: &'static str, code: i32) -> io::Error {
    io::Error::other(NativeFailure {
        operation,
        code: code.cast_unsigned(),
    })
}
