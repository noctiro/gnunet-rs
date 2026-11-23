use super::*;

#[test]
fn borrows_the_original_data_and_distinguishes_invalid_parameters() -> Result<(), Error> {
    let data = [7; 32];
    let association = Association::from_fields(3, 1, 1, &data)?;
    if association.usage() != Usage::DaneEndEntity
        || association.selector() != Selector::SubjectPublicKeyInfo
        || association.matching() != Matching::Sha256(&data)
        || Association::from_fields(3, 1, 1, &data[..31]) != Err(Error::Malformed)
        || Association::from_fields(3, 1, 2, &data) != Err(Error::Malformed)
        || Association::from_fields(3, 1, 0, &[]) != Err(Error::Malformed)
        || Association::from_fields(4, 1, 1, &data) != Err(Error::Unsupported)
        || Association::from_fields(3, 2, 1, &data) != Err(Error::Unsupported)
        || Association::from_fields(3, 1, 3, &data) != Err(Error::Unsupported)
        || Association::parse(&[3, 1]) != Err(Error::Truncated)
    {
        return Err(Error::Conflict);
    }
    let wire = b"\x03\0\0\x30\x01\0";
    if Association::parse(wire)?.matching() != Matching::Exact(&wire[3..]) {
        return Err(Error::Conflict);
    }
    Ok(())
}

#[cfg(feature = "tlsa-hash")]
#[test]
fn compares_the_exact_selected_bytes_for_all_supported_methods() -> Result<(), Error> {
    let der = b"abc";
    let sha256 = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    let sha512 = [
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41,
        0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55,
        0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3,
        0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f,
        0xa5, 0x4c, 0xa4, 0x9f,
    ];
    for (kind, data) in [(0, der.as_slice()), (1, &sha256), (2, &sha512)] {
        let association = Association::from_fields(3, 1, kind, data)?;
        if !association.matches_selected(der) || association.matches_selected(b"aBc") {
            return Err(Error::Authentication);
        }
    }
    Ok(())
}
