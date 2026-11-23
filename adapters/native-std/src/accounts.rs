//! Read bounded, owned records from the native Unix account databases.

use std::{
    ffi::{CStr, CString},
    io,
    mem::MaybeUninit,
    ptr, slice,
};

/// One account as returned by the native user database.
pub struct Account {
    name: CString,
    uid: u32,
    gid: u32,
}

impl Account {
    /// Original account name bytes.
    #[must_use]
    pub fn name(&self) -> &CStr {
        &self.name
    }

    /// Native numeric user ID.
    #[must_use]
    pub const fn uid(&self) -> u32 {
        self.uid
    }

    /// Native primary group ID.
    #[must_use]
    pub const fn gid(&self) -> u32 {
        self.gid
    }

    /// Check current database membership and require a registered group entry.
    /// This queries the account database, independently of process credentials.
    ///
    /// # Errors
    /// Returns native group lookup failures or invalid or oversized group lists.
    #[cfg(not(any(target_os = "aix", target_os = "emscripten")))]
    #[expect(
        unsafe_code,
        reason = "getgrouplist borrows a bounded native group array"
    )]
    pub fn belongs_to_group(&self, gid: u32) -> io::Result<bool> {
        const INITIAL_GROUPS: usize = 16;
        const MAX_GROUPS: usize = 65_536;
        #[cfg(target_vendor = "apple")]
        let (primary, target) = (self.gid.cast_signed(), gid.cast_signed());
        #[cfg(not(target_vendor = "apple"))]
        let (primary, target) = (self.gid, gid);

        let mut initial = [0; INITIAL_GROUPS];
        let mut larger = Vec::new();
        let mut capacity = INITIAL_GROUPS;
        loop {
            let groups = if capacity == INITIAL_GROUPS {
                &mut initial[..]
            } else {
                larger
                    .try_reserve_exact(capacity - larger.len())
                    .map_err(out_of_memory)?;
                larger.resize(capacity, 0);
                &mut larger[..]
            };
            let mut used = capacity as libc::c_int;
            // SAFETY: the name is owned and groups contains exactly `used` writable
            // native group slots. libc uses both only for this synchronous call.
            let status = unsafe {
                libc::getgrouplist(self.name.as_ptr(), primary, groups.as_mut_ptr(), &mut used)
            };
            let used = usize::try_from(used)
                .map_err(|_| invalid("native account lookup returned an invalid group count"))?;
            if status >= 0 {
                // BSD returns 0 on success. Linux and Android return the group count.
                if used == 0 || used > capacity || (status > 0 && status as usize != used) {
                    return Err(invalid(
                        "native account lookup returned an invalid group count",
                    ));
                }
                if !groups[..used].contains(&target) {
                    return Ok(false);
                }
                return read_group(gid, |_| Ok(())).map(|group| group.is_some());
            }
            // Darwin reports the copied count on overflow, not the total.
            #[cfg(target_vendor = "apple")]
            let used = if used == capacity { capacity * 2 } else { used };
            if status != -1 || used <= capacity {
                return Err(io::Error::other("native account group enumeration failed"));
            }
            if used > MAX_GROUPS {
                return Err(invalid(
                    "native account group list exceeds the lookup limit",
                ));
            }
            capacity = used;
        }
    }

    /// This native platform does not export `getgrouplist`.
    ///
    /// # Errors
    /// Returns [`io::ErrorKind::Unsupported`].
    #[cfg(any(target_os = "aix", target_os = "emscripten"))]
    pub fn belongs_to_group(&self, _: u32) -> io::Result<bool> {
        Err(io::ErrorKind::Unsupported.into())
    }
}

/// Resolve a numeric UID using the native user database.
///
/// # Errors
/// Returns native database errors, allocation failures or an invalid record.
pub fn user_by_uid(uid: u32) -> io::Result<Option<Account>> {
    read_user(UserQuery::Uid(uid))
}

/// Resolve a NUL-terminated account name using the native user database.
///
/// # Errors
/// Returns native database errors, allocation failures or an invalid record.
pub fn user_by_name(name: &CStr) -> io::Result<Option<Account>> {
    read_user(UserQuery::Name(name))
}

/// Resolve a numeric GID to an original, owned group name.
///
/// # Errors
/// Returns native database errors, allocation failures or an invalid record.
pub fn group_name(gid: u32) -> io::Result<Option<CString>> {
    read_group(gid, copy_name)
}

enum UserQuery<'a> {
    Uid(u32),
    Name(&'a CStr),
}

#[expect(
    unsafe_code,
    reason = "reentrant passwd queries write a caller-owned record"
)]
fn read_user(query: UserQuery<'_>) -> io::Result<Option<Account>> {
    // SAFETY: libc initializes the matching passwd record on success and uses
    // only the bounded scratch buffer for the returned name. The name query
    // supplies a live NUL-terminated input.
    unsafe {
        lookup(
            |record, scratch, bytes, matched| match query {
                UserQuery::Uid(uid) => libc::getpwuid_r(uid, record, scratch, bytes, matched),
                UserQuery::Name(name) => {
                    libc::getpwnam_r(name.as_ptr(), record, scratch, bytes, matched)
                }
            },
            |entry, scratch| {
                Ok(Account {
                    name: copy_name(name_in_buffer(entry.pw_name, scratch)?)?,
                    uid: entry.pw_uid,
                    gid: entry.pw_gid,
                })
            },
        )
    }
}

#[expect(
    unsafe_code,
    reason = "reentrant group query writes a caller-owned record"
)]
fn read_group<T>(gid: u32, use_name: impl FnOnce(&CStr) -> io::Result<T>) -> io::Result<Option<T>> {
    // SAFETY: libc initializes the matching group record on success and uses
    // only the bounded scratch buffer for the returned name.
    unsafe {
        lookup(
            |record, scratch, bytes, matched| {
                libc::getgrgid_r(gid, record, scratch, bytes, matched)
            },
            |entry, scratch| use_name(name_in_buffer(entry.gr_name, scratch)?),
        )
    }
}

/// The native callback must initialize the supplied record when returning it and
/// write only within the record, result slot and supplied scratch extent.
#[expect(
    unsafe_code,
    reason = "matching native records and aligned scratch are validated"
)]
unsafe fn lookup<R, T>(
    mut read: impl FnMut(*mut R, *mut libc::c_char, usize, *mut *mut R) -> libc::c_int,
    use_record: impl FnOnce(R, &[u8]) -> io::Result<T>,
) -> io::Result<Option<T>> {
    // Group records may place member pointers alongside strings in the scratch.
    const INITIAL_WORDS: usize = 1024 / size_of::<usize>();
    const MAX_WORDS: usize = (1024 * 1024) / size_of::<usize>();
    let mut scratch = Vec::<usize>::new();
    let mut words = INITIAL_WORDS;
    loop {
        scratch
            .try_reserve_exact(words - scratch.len())
            .map_err(out_of_memory)?;
        scratch.resize(words, usize::MAX);
        let mut record = MaybeUninit::<R>::uninit();
        let mut matched = ptr::null_mut();
        let bytes = size_of_val(scratch.as_slice());
        let status = read(
            record.as_mut_ptr(),
            scratch.as_mut_ptr().cast(),
            bytes,
            &mut matched,
        );
        match status {
            0 if matched.is_null() => return Ok(None),
            0 if matched == record.as_mut_ptr() => {
                // SAFETY: the matching native result initialized this record. Scratch
                // was initialized before the call and is owned until use_record returns.
                let (entry, scratch) = unsafe {
                    (
                        record.assume_init(),
                        slice::from_raw_parts(scratch.as_ptr().cast(), bytes),
                    )
                };
                return use_record(entry, scratch).map(Some);
            }
            0 => return Err(invalid("native account lookup returned an unknown record")),
            // Bionic returns ENOENT with a null match for an absent account.
            #[cfg(target_os = "android")]
            libc::ENOENT if matched.is_null() => return Ok(None),
            libc::ERANGE if words < MAX_WORDS => {
                scratch.fill(usize::MAX);
                words *= 2;
            }
            code => return Err(io::Error::from_raw_os_error(code)),
        }
    }
}

fn name_in_buffer(name: *const libc::c_char, scratch: &[u8]) -> io::Result<&CStr> {
    let start = name.addr().checked_sub(scratch.as_ptr().addr());
    start
        .and_then(|start| scratch.get(start..))
        .and_then(|bytes| CStr::from_bytes_until_nul(bytes).ok())
        .ok_or_else(|| invalid("native account lookup returned an invalid name"))
}

fn copy_name(name: &CStr) -> io::Result<CString> {
    let bytes = name.to_bytes_with_nul();
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(out_of_memory)?;
    owned.extend_from_slice(bytes);
    CString::from_vec_with_nul(owned).map_err(|_| invalid("native account name is invalid"))
}

fn out_of_memory(_: std::collections::TryReserveError) -> io::Error {
    io::ErrorKind::OutOfMemory.into()
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
