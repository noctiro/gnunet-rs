//! Original directory leases, single-component access and private creation.
use super::{leaf::Leaf, link, open, rename, sync};
use crate::filesystem::CreateDirectoryError;
use crate::paths::metadata;
use std::{ffi::OsStr, fs::File, io, os::windows::fs::OpenOptionsExt, path::Path};
use windows_sys::{
    Wdk::Storage::FileSystem::{
        FILE_CREATE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_IF,
    },
    Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE,
    },
};
const DIRECTORY_SHARING: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
const SOURCE_SHARING: u32 = FILE_SHARE_READ | FILE_SHARE_DELETE;
const FILE_SHARING: u32 = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
/// Held ordinary directory, independent of its later pathname. General owners
/// permit compatible metadata mutation; explicit source constructors retain a
/// read-only sharing fence. Child names remain exact native components.
#[derive(Debug)]
pub struct Directory {
    file: File,
}
impl Directory {
    /// Open the selected directory without following its final reparse point.
    /// Ancestors resolve normally; this selects a root, not a pathname sandbox.
    ///
    /// # Errors
    /// Preserves open/sharing/metadata errors; refuses name-surrogate roots.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::options()
            .read(true)
            .share_mode(DIRECTORY_SHARING)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        Self::checked(file)
    }
    /// Open an original source directory with a read-only sharing fence.
    /// Other generic-write opens are refused while this lease lives; this is
    /// not whole-tree immutability or namespace exclusion.
    pub fn open_source(path: &Path) -> io::Result<Self> {
        Self::checked(
            File::options()
                .read(true)
                .share_mode(SOURCE_SHARING)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(path)?,
        )
    }
    /// Reopen this exact original directory for ordinary metadata operations.
    /// The borrowed original stays with the caller on either outcome.
    pub fn from_file(file: &File) -> io::Result<Self> {
        Self::checked(open::reopen(
            file,
            FILE_GENERIC_READ,
            DIRECTORY_SHARING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?)
    }
    /// Reopen the same source object with an independent read-only sharing fence.
    /// The original remains with its caller; no pathname is resolved.
    pub fn from_source_file(file: &File) -> io::Result<Self> {
        Self::checked(open::reopen(
            file,
            FILE_GENERIC_READ,
            SOURCE_SHARING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )?)
    }
    fn checked(file: File) -> io::Result<Self> {
        Self::validate_handle(&file)?;
        Ok(Self { file })
    }
    pub(super) fn validate_handle(file: &File) -> io::Result<()> {
        let info = metadata::attributes(file)?;
        if info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY == 0
            || info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
                && info.ReparseTag & 0x2000_0000 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ordinary directory handle required",
            ));
        }
        Ok(())
    }
    /// Borrow the held original directory without granting a pathname binding.
    pub fn as_file(&self) -> &File {
        &self.file
    }
    /// Transfer the original directory handle without resolving a pathname.
    pub fn into_file(self) -> File {
        self.file
    }
    /// Observe a child through an attributes-only no-follow open. Name-surrogate
    /// and special objects are classified without reading their contents.
    pub fn entry_info(&self, name: &OsStr) -> io::Result<crate::filesystem::EntryInfo> {
        use windows_sys::Win32::Storage::FileSystem::FILE_READ_ATTRIBUTES;
        let mut leaf = Leaf::new(name)?;
        let (file, _) = open::child(
            &self.file,
            &mut leaf,
            FILE_READ_ATTRIBUTES,
            FILE_SHARING,
            FILE_OPEN,
            0,
            None,
        )?;
        crate::filesystem::file_info(&file)
    }
    /// Enumerate this original directory through an independent native cursor.
    /// Collection, entry validation and change detection remain caller-owned.
    pub fn entries(&self) -> io::Result<crate::filesystem::Entries> {
        crate::filesystem::Entries::open(&self.file)
    }
    /// Duplicate this original owner without resolving a pathname.
    pub fn duplicate(&self) -> io::Result<Self> {
        Ok(Self {
            file: self.file.try_clone()?,
        })
    }
    /// Qualify this held directory's process-user owner and private DACL.
    /// Existing security is retained; administrative principals remain trusted.
    pub fn validate_private(&self) -> io::Result<()> {
        crate::identity::validate_private(&self.file)
    }
    /// Require a trusted owner and DACL excluding untrusted namespace writes.
    /// Read/traverse access is allowed; administrative principals remain trusted.
    pub fn validate_namespace(&self) -> io::Result<()> {
        crate::identity::validate_parent(&self.file)
    }
    /// Synchronize the held local NTFS directory. Other filesystems return
    /// `Unavailable`, as do permissions or sharing that exclude a writable
    /// lease. Reopening uses the original handle without resolving a name.
    /// Other open and flush failures are returned to the caller.
    pub fn sync(&self) -> io::Result<crate::DirectorySync> {
        sync::directory(&self.file)
    }
    /// Exclusively create an ordinary child with normal inherited permissions.
    /// The NT create request returns the original handle directly.
    ///
    /// # Errors
    /// Preserves native creation failures and rejects invalid child names.
    pub fn create_directory(&self, name: &OsStr) -> Result<Self, CreateDirectoryError> {
        let mut leaf = Leaf::new(name).map_err(CreateDirectoryError::Create)?;
        let (file, _) = open::child(
            &self.file,
            &mut leaf,
            FILE_GENERIC_READ,
            DIRECTORY_SHARING,
            FILE_CREATE,
            FILE_DIRECTORY_FILE,
            None,
        )
        .map_err(CreateDirectoryError::Create)?;
        Ok(Self { file })
    }
    /// Create one protected current-user-only directory, refusing an existing
    /// name. A later native failure can leave the new directory present.
    pub fn create_private_directory(&self, name: &OsStr) -> io::Result<Self> {
        let mut leaf = Leaf::new(name)?;
        let descriptor = crate::identity::private_file_descriptor()?;
        let (file, _) = open::child(
            &self.file,
            &mut leaf,
            FILE_GENERIC_READ,
            DIRECTORY_SHARING,
            FILE_CREATE,
            FILE_DIRECTORY_FILE,
            Some(&descriptor),
        )?;
        Ok(Self { file })
    }
    /// Open an existing child directory without following name surrogates.
    pub fn open_directory(&self, name: &OsStr) -> io::Result<Self> {
        let mut leaf = Leaf::new(name)?;
        let (file, _) = open::child(
            &self.file,
            &mut leaf,
            FILE_GENERIC_READ,
            DIRECTORY_SHARING,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            None,
        )?;
        Self::checked(file)
    }
    /// Open a no-follow source child with its read-only sharing fence already set.
    pub fn open_source_directory(&self, name: &OsStr) -> io::Result<Self> {
        let mut leaf = Leaf::new(name)?;
        let (file, _) = open::child(
            &self.file,
            &mut leaf,
            FILE_GENERIC_READ,
            SOURCE_SHARING,
            FILE_OPEN,
            FILE_DIRECTORY_FILE,
            None,
        )?;
        Self::checked(file)
    }
    /// Create a protected current-user-only directory or open an existing one.
    /// Existing security is retained; callers separately qualify its trust.
    /// Creation can leave a directory if a later operation fails. Callers own
    /// namespace/ACL administration and exclude thread impersonation at creation.
    pub fn ensure_directory(&self, name: &OsStr) -> io::Result<Self> {
        let mut leaf = Leaf::new(name)?;
        let descriptor = crate::identity::private_file_descriptor()?;
        let (file, information) = open::child(
            &self.file,
            &mut leaf,
            FILE_GENERIC_READ,
            DIRECTORY_SHARING,
            FILE_OPEN_IF,
            FILE_DIRECTORY_FILE,
            Some(&descriptor),
        )?;
        // FILE_CREATED is 2: the protected owner-only descriptor was installed
        // at creation. Callers still exclude namespace/ACL administration.
        if information == 2 {
            Ok(Self { file })
        } else {
            Self::checked(file)
        }
    }
    /// Ensure one private directory owned by the actual process user. Existing
    /// owner/DACL grants are checked on its held handle; unknown ACE forms and
    /// nonadministrative data grants fail closed. Existing ACLs are not changed.
    pub fn ensure_private_directory(&self, name: &OsStr) -> io::Result<Self> {
        let directory = self.ensure_directory(name)?;
        crate::identity::validate_private(directory.as_file())?;
        Ok(directory)
    }
    /// Exclusively create one private unnamed file stream. No existing name is
    /// replaced, and no reparse point is followed. The file is synchronous and
    /// includes DELETE access for explicit original-object cleanup/publication.
    pub fn create_private_file(&self, name: &OsStr) -> io::Result<File> {
        let mut leaf = Leaf::new(name)?;
        let descriptor = crate::identity::private_file_descriptor()?;
        let (file, _) = open::child(
            &self.file,
            &mut leaf,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | DELETE,
            FILE_SHARING,
            FILE_CREATE,
            FILE_NON_DIRECTORY_FILE,
            Some(&descriptor),
        )?;
        Ok(file)
    }
    /// Open one actual child disk-file stream for reading. Name surrogates and
    /// AF_UNIX nodes are refused before reading content.
    pub fn open_file(&self, name: &OsStr) -> io::Result<File> {
        self.open_regular(name, FILE_GENERIC_READ)
    }
    /// Open an existing ordinary stream with the write access required by
    /// Windows file-data synchronization. This never creates or truncates it.
    pub fn open_file_for_update(&self, name: &OsStr) -> io::Result<File> {
        self.open_regular(name, FILE_GENERIC_READ | FILE_GENERIC_WRITE)
    }
    /// Open with the write access required by Windows file-data synchronization.
    /// Existing names are never created or truncated.
    pub fn open_file_for_sync(&self, name: &OsStr) -> io::Result<File> {
        self.open_file_for_update(name)
    }
    fn open_regular(&self, name: &OsStr, access: u32) -> io::Result<File> {
        let mut leaf = Leaf::new(name)?;
        let (file, _) = open::child(
            &self.file,
            &mut leaf,
            access,
            FILE_SHARING,
            FILE_OPEN,
            FILE_NON_DIRECTORY_FILE,
            None,
        )?;
        if !metadata::is_regular_file(&file)? {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "ordinary file stream required",
            ));
        }
        Ok(file)
    }
    /// Compare a current child with a still-held original file object. Names
    /// alone never authorize cleanup; the original pin prevents ID reuse.
    pub fn same_file(&self, name: &OsStr, original: &File) -> io::Result<bool> {
        let current = self.open_file(name)?;
        Ok(metadata::FileIdentity::of(&current)? == metadata::FileIdentity::of(original)?)
    }
    /// Atomically replace a child name with the original single-link source.
    /// Source selection is checked on its captured handle; callers exclude
    /// concurrent namespace changes. Existing target handles retain their old
    /// objects. No data or directory synchronization is performed.
    ///
    /// # Errors
    /// Preserves native errors and refuses a changed source. An error can follow
    /// a visible replacement; callers retain their original mutation uncertainty.
    pub fn replace_file(
        &self,
        source_name: &OsStr,
        original: &File,
        target_name: &OsStr,
    ) -> io::Result<()> {
        rename::regular_file(
            &self.file,
            source_name,
            original,
            target_name,
            rename::Mode::Replace,
        )?;
        if !self.same_file(target_name, original)? {
            return Err(io::Error::other("original replacement target changed"));
        }
        Ok(())
    }
    /// Move the captured single-link source to an absent child name. The
    /// publication owner verifies the installed name and handles synchronization.
    pub(crate) fn rename_new_file(
        &self,
        source_name: &OsStr,
        original: &File,
        target_name: &OsStr,
    ) -> io::Result<()> {
        // Alternate spellings, such as an NTFS short alias, can select the
        // stage itself. Other collisions and lookup failures go to the native
        // no-replace request for authoritative classification.
        if self.same_file(target_name, original).is_ok_and(|same| same) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        rename::regular_file(
            &self.file,
            source_name,
            original,
            target_name,
            rename::Mode::Create,
        )
    }
    /// Link the original regular source at a new child name atomically. Existing
    /// names and cross-volume moves are refused; no copy/replace fallback exists.
    /// Callers serialize source content/stream changes. This publishes a name,
    /// independently of file-data or directory synchronization.
    pub fn link_file(&self, source: &File, name: &OsStr) -> io::Result<()> {
        link::create(&self.file, source, name)
    }
    /// Publish a new hard link to a still-held original after checking its
    /// source entry. The native link request uses the original file object.
    /// This is independent of data and directory synchronization.
    pub fn link_file_from(
        &self,
        source_parent: &Self,
        source_name: &OsStr,
        source: &File,
        name: &OsStr,
    ) -> io::Result<()> {
        if !source_parent.same_file(source_name, source)? {
            return Err(io::Error::other("original link source changed"));
        }
        self.link_file(source, name)
    }
    /// Remove only a named link still matching a held original file object.
    /// The captured link handle prevents a later pathname replacement from
    /// retargeting deletion. Native sharing/disposition failures remain errors.
    pub fn remove_file(&self, name: &OsStr, original: &File) -> io::Result<()> {
        link::remove(&self.file, name, original)
    }
}
