use super::super::icc;
use super::*;
use jpxl_bitstream::BitWriter;
use jpxl_decode::icc::NUM_ICC_CONTEXTS;
use jpxl_entropy::{
    CodingMode, ContextMap, EncoderPlan, EntropyTables, HybridUintConfig, SymbolEncoder,
    TokenCensus,
};
use std::{convert::Infallible, error::Error};

fn fixture() -> Result<(Vec<u8>, Vec<u8>), Box<dyn Error>> {
    const TAG_BYTES: usize = 512;
    const PROFILE_BYTES: usize = 144 + TAG_BYTES;
    let mut profile = icc::fixture()[..144].to_vec();
    profile[..4].copy_from_slice(&(PROFILE_BYTES as u32).to_be_bytes());
    profile[68..80].copy_from_slice(b"\0\0\xf6\xd6\0\x01\0\0\0\0\xd3\x2d");
    profile[140..144].copy_from_slice(&(TAG_BYTES as u32).to_be_bytes());
    profile.extend((0..TAG_BYTES).map(|i| (i ^ (i >> 8)) as u8));

    // E.4.2: output size, four command bytes. E.4.4 skips tag prediction and
    // E.4.5 inserts the remaining 528 bytes literally. The header residuals are zero.
    let mut encoded = vec![0x90, 5, 4, 0, 1, 0x90, 4];
    encoded.resize(encoded.len() + 128, 0);
    encoded.extend_from_slice(&profile[128..]);

    let mut bits = BitWriter::new();
    bits.write_bits(16, 0x0aff)?;
    bits.write_bit(true);
    bits.write_bits(5, 0)?;
    bits.write_bits(3, 1)?; // Square, 8x8.
    bits.write_bits(2, 0)?; // Nondefault metadata, no extra fields.
    bits.write_bits(3, 0)?; // Integer, eight bits per sample.
    bits.write_bit(true); // 16-bit modular buffers.
    bits.write_bits(2, 0)?; // No extra channels.
    bits.write_bit(false); // Not XYB.
    bits.write_bit(false); // Explicit colour encoding.
    bits.write_bit(true); // Embedded ICC.
    bits.write_bits(2, 0)?; // RGB.
    bits.write_u64(0)?; // No extensions.
    bits.write_bit(true); // Default transform weights.
    bits.write_u64(encoded.len() as u64)?;

    let plan = EncoderPlan::clustered(
        ContextMap::new(vec![0; NUM_ICC_CONTEXTS])?,
        CodingMode::Ans,
        vec![HybridUintConfig {
            split_exponent: 4,
            msb_in_token: 0,
            lsb_in_token: 0,
        }],
    )?;
    let mut census = TokenCensus::new(NUM_ICC_CONTEXTS)?;
    for &byte in &encoded {
        census.record(0, byte.into())?;
    }
    let tables = EntropyTables::build(&plan, &census)?;
    tables.write_bundle(&mut bits)?;
    let mut encoder = SymbolEncoder::new(&tables);
    for byte in encoded {
        encoder.push_uint(0, byte.into())?;
    }
    encoder.write_stream(&mut bits)?;
    Ok((bits.into_bytes(), profile))
}

fn box_bytes(kind: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut bytes = ((data.len() + 8) as u32).to_be_bytes().to_vec();
    bytes.extend_from_slice(kind);
    bytes.extend_from_slice(data);
    bytes
}

fn fragment(index: u32, bytes: &[u8]) -> Vec<u8> {
    let data = [index.to_be_bytes().as_slice(), bytes].concat();
    box_bytes(b"jxlp", &data)
}

#[test]
fn publishes_exact_profile_from_bare_boxed_and_reordered_prefixes() -> Result<(), Box<dyn Error>> {
    let (stream, profile) = fixture()?;
    let file_type = box_bytes(b"ftyp", b"jxl \0\0\0\x01jxl ");
    let payload = box_bytes(b"jxlc", &stream);
    let boxed = [SIGNATURE.as_slice(), &file_type, &payload].concat();
    let (first, last) = stream.split_at(261);
    let reordered = [
        SIGNATURE.as_slice(),
        &file_type,
        &fragment(0x8000_0001, last),
        &fragment(0, first),
    ]
    .concat();
    for bytes in [&stream, &boxed, &reordered] {
        for limit in [profile.len(), profile.len() - 1] {
            let mut scratch = [0; 2048];
            let input = Input::new(
                &bytes[..32],
                bytes.len() as u64,
                &mut scratch,
                |at, out: &mut [u8]| {
                    let at = at as usize;
                    out.copy_from_slice(&bytes[at..at + out.len()]);
                    Ok(())
                },
            );
            let mut observed = None;
            let mut geometry = false;
            let Ok(()) = visit(
                input,
                FieldLimits {
                    text: 64,
                    icc: limit,
                },
                &mut |field| {
                    match field {
                        Field::ColorProfile(profile) => observed = Some(profile.bytes().to_vec()),
                        Field::Text(112, b"8x8") => geometry = true,
                        _ => {}
                    }
                    Ok::<_, Infallible>(())
                },
            );
            let expected = (limit == profile.len()).then_some(profile.as_slice());
            if !geometry || observed.as_deref() != expected {
                return Err(format!(
                    "expected 8x8 and ICC {:?}, read {geometry} and {:?}",
                    expected.map(<[u8]>::len),
                    observed.as_ref().map(Vec::len)
                )
                .into());
            }
        }
    }
    Ok(())
}

#[test]
fn bounded_profile_read_leaves_positioned_xml_available() -> Result<(), Box<dyn Error>> {
    const XMP: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Oslo"/></r:RDF>"#;
    let (stream, _) = fixture()?;
    let file_type = box_bytes(b"ftyp", b"jxl \0\0\0\0jxl ");
    let codestream = box_bytes(b"jxlc", &stream);
    let packet = box_bytes(b"xml ", XMP);
    let bytes = [SIGNATURE.as_slice(), &file_type, &codestream, &packet].concat();
    let mut scratch = [0; 220];
    let input = Input::new(
        &bytes[..32],
        bytes.len() as u64,
        &mut scratch,
        |at, out: &mut [u8]| {
            let at = at as usize;
            out.copy_from_slice(&bytes[at..at + out.len()]);
            Ok(())
        },
    );
    let mut city = false;
    let mut profile = false;
    let Ok(()) = visit(
        input,
        FieldLimits {
            text: 64,
            icc: 1024,
        },
        &mut |field| {
            city |= matches!(field, Field::Text(41, b"Oslo"));
            profile |= matches!(field, Field::ColorProfile(_));
            Ok::<_, Infallible>(())
        },
    );
    if !city || profile {
        return Err("positioned XMP must fit before the optional profile is attempted".into());
    }
    Ok(())
}
