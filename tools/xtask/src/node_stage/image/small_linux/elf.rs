//! Verify the published Cortex-A7 soft-float Linux executable.
use super::Result;
use std::{
    fs::File,
    io::{Read, Seek, SeekFrom},
    path::Path,
};

const ELF_HEADER_SIZE: usize = 52;
const PROGRAM_HEADER_SIZE: usize = 32;
const EM_ARM: u16 = 40;
const EF_ARM_EABI_VER5: u32 = 0x0500_0000;
const EF_ARM_ABI_FLOAT_HARD: u32 = 0x400;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PF_X: u32 = 1;
const DT_NULL: u32 = 0;
const DT_NEEDED: u32 = 1;
const DT_AUXILIARY: u32 = 0x7fff_fffd;
const DT_FILTER: u32 = 0x7fff_ffff;

pub(super) fn validate_file(path: &Path) -> Result<()> {
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    validate(&mut file, size)
}

fn validate(file: &mut (impl Read + Seek), file_size: u64) -> Result<()> {
    let mut header = [0; ELF_HEADER_SIZE];
    file.read_exact(&mut header)?;
    let flags = word(&header, 36);
    let entry = word(&header, 24) & !1;
    if !header.starts_with(b"\x7fELF\x01\x01\x01")
        || !matches!(halfword(&header, 16), 2 | 3)
        || halfword(&header, 18) != EM_ARM
        || word(&header, 20) != 1
        || entry == 0
        || flags & 0xff00_0000 != EF_ARM_EABI_VER5
        || flags & EF_ARM_ABI_FLOAT_HARD != 0
    {
        return Err("expected a little-endian ARM EABI5 executable with soft float ABI".into());
    }

    let offset = u64::from(word(&header, 28));
    let stride = u64::from(halfword(&header, 42));
    let count = u64::from(halfword(&header, 44));
    if usize::from(halfword(&header, 40)) != ELF_HEADER_SIZE
        || offset < ELF_HEADER_SIZE as u64
        || stride != PROGRAM_HEADER_SIZE as u64
        || count == 0
        || count == u64::from(u16::MAX)
        || offset + stride * count > file_size
    {
        return Err("invalid ELF program header table".into());
    }

    let mut entry_in_file = false;
    for index in 0..count {
        let mut program = [0; PROGRAM_HEADER_SIZE];
        file.seek(SeekFrom::Start(offset + index * stride))?;
        file.read_exact(&mut program)?;
        let file_offset = u64::from(word(&program, 4));
        let bytes = u64::from(word(&program, 16));
        if file_offset + bytes > file_size {
            return Err("ELF segment exceeds file size".into());
        }
        match word(&program, 0) {
            PT_LOAD if word(&program, 24) & PF_X != 0 => {
                let first = u64::from(word(&program, 8));
                entry_in_file |= (first..first + bytes).contains(&u64::from(entry));
            }
            PT_DYNAMIC => check_dynamic(file, file_offset, bytes)?,
            PT_INTERP => {
                return Err("static Linux image requires an ELF without an interpreter".into());
            }
            _ => {}
        }
    }
    if !entry_in_file {
        return Err("ELF entry must point to file-backed executable code".into());
    }
    Ok(())
}

fn check_dynamic(file: &mut (impl Read + Seek), offset: u64, bytes: u64) -> Result<()> {
    let mut item = [0; 8];
    let stride = item.len() as u64;
    if !bytes.is_multiple_of(stride) {
        return Err("invalid ELF dynamic table".into());
    }
    file.seek(SeekFrom::Start(offset))?;
    for _ in 0..bytes / stride {
        file.read_exact(&mut item)?;
        match word(&item, 0) {
            DT_NULL => return Ok(()),
            DT_NEEDED | DT_AUXILIARY | DT_FILTER => {
                return Err("static Linux image cannot require shared libraries".into());
            }
            _ => {}
        }
    }
    Err("ELF dynamic table has no terminator".into())
}

fn halfword(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn word(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn set_word(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn fixture() -> [u8; 124] {
        let mut file = [0; 124];
        file[..7].copy_from_slice(b"\x7fELF\x01\x01\x01");
        file[16] = 3;
        file[18] = EM_ARM as u8;
        set_word(&mut file, 20, 1);
        set_word(&mut file, 24, 0x101);
        set_word(&mut file, 28, ELF_HEADER_SIZE as u32);
        set_word(&mut file, 36, EF_ARM_EABI_VER5);
        file[40] = ELF_HEADER_SIZE as u8;
        file[42] = PROGRAM_HEADER_SIZE as u8;
        file[44] = 2;

        set_word(&mut file, 52, PT_LOAD);
        set_word(&mut file, 60, 0x100);
        set_word(&mut file, 68, 124);
        set_word(&mut file, 72, 124);
        set_word(&mut file, 76, PF_X);

        set_word(&mut file, 84, PT_DYNAMIC);
        set_word(&mut file, 88, 116);
        set_word(&mut file, 100, 8);
        set_word(&mut file, 104, 8);
        file
    }

    #[test]
    fn accepts_static_pie_and_refuses_dynamic_or_mismatched_artifacts() -> Result<()> {
        let fixture = fixture();
        validate(&mut Cursor::new(fixture), fixture.len() as u64)?;
        for (field, value) in [
            (36, EF_ARM_EABI_VER5 | EF_ARM_ABI_FLOAT_HARD),
            (84, PT_INTERP),
            (116, DT_NEEDED),
            (28, u32::MAX),
            (76, 0),
        ] {
            let mut invalid = fixture;
            set_word(&mut invalid, field, value);
            if validate(&mut Cursor::new(invalid), invalid.len() as u64).is_ok() {
                return Err(format!("accepted an invalid ARM ELF field at offset {field}").into());
            }
        }
        Ok(())
    }
}
