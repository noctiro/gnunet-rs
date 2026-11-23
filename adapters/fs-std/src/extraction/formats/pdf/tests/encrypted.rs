use std::error::Error;
use std::io::Write;

use super::{FORMAT, Input, PAGE_COUNT, visit};

// QPDF generated these one-page fixtures from the same synthetic metadata.
// R2 through R4 and R6 have empty user passwords. R5 has only an empty owner
// password. R6 leaves the catalog outside the encrypted object stream.
const R6: &[u8] = include_bytes!("fixtures/r6-object-stream.pdf");
const R4: &[u8] = include_bytes!("fixtures/r4-aes128.pdf");
const OPENABLE: &[(&str, &[u8], &[u8])] = &[
    ("R2 RC4", include_bytes!("fixtures/r2-rc4.pdf"), b"PDF 1.3"),
    ("R3 RC4", include_bytes!("fixtures/r3-rc4.pdf"), b"PDF 1.4"),
    ("R4 AES-128", R4, b"PDF 1.6"),
    (
        "R5 AES-256",
        include_bytes!("fixtures/r5-empty-owner.pdf"),
        b"PDF 1.7",
    ),
    ("R6 AES-256", R6, b"PDF 2.0"),
];

type Fields = Vec<(u32, Vec<u8>)>;

#[test]
fn standard_encryption_revisions_use_the_implicit_empty_password() -> Result<(), Box<dyn Error>> {
    for &(variant, pdf, version) in OPENABLE {
        expect_fields(variant, pdf, version)?;
    }
    Ok(())
}

#[test]
fn stream_filter_is_independent_of_the_string_filter() -> Result<(), Box<dyn Error>> {
    const ORIGINAL: &[u8] = b"/StmF /StdCF /StrF /StdCF /U <";
    const REPLACEMENT: &[u8; ORIGINAL.len()] = b"/StmF/StdCF/StrF/Identity /U <";
    let mut pdf = R6.to_vec();
    let start = pdf
        .windows(ORIGINAL.len())
        .position(|window| window == ORIGINAL)
        .ok_or("stream and string filters missing")?;
    // Info strings are inside the object stream and the trailer ID is
    // exempt. Changing StrF leaves all source bytes and offsets valid.
    pdf[start..start + REPLACEMENT.len()].copy_from_slice(REPLACEMENT);
    expect_fields("R6 with independent filters", &pdf, b"PDF 2.0")
}

#[test]
fn explicit_named_crypt_filter_overrides_the_stream_default() -> Result<(), Box<dyn Error>> {
    const DEFAULTS: &[u8] = b"/StmF /StdCF /StrF /StdCF /U <";
    const IDENTITY_STREAMS: &[u8; DEFAULTS.len()] = b"/StmF/Identity/StrF/StdCF /U <";
    const STREAM: &[u8] = b"2 0 obj\n<< /Type /ObjStm";
    const END: &[u8] = b"endstream\nendobj\n";
    const FILTER: &[u8] = b"/Filter /FlateDecode";
    let locate = |bytes: &[u8], pattern: &[u8]| {
        bytes
            .windows(pattern.len())
            .position(|window| window == pattern)
            .ok_or("expected marker in the encryption fixture")
    };
    let record = &R6[locate(R6, STREAM)?..];
    let record = &record[..locate(record, END)? + END.len()];
    let filter_at = locate(record, FILTER)?;
    let file_id = &R6[locate(R6, b"/ID [")?..];
    let file_id = &file_id[..locate(file_id, b"]")? + 1];
    let footer = &R6[locate(R6, b"startxref\n")? + b"startxref\n".len()..];
    let previous = std::str::from_utf8(&footer[..locate(footer, b"\n")?])?.parse::<u64>()?;

    let mut pdf = R6.to_vec();
    let defaults = locate(&pdf, DEFAULTS)?;
    pdf[defaults..defaults + DEFAULTS.len()].copy_from_slice(IDENTITY_STREAMS);
    let replacement_at = pdf.len();
    pdf.extend_from_slice(&record[..filter_at]);
    pdf.extend_from_slice(b"/Filter [/Crypt /FlateDecode] /DecodeParms [<< /Name /StdCF >> null]");
    pdf.extend_from_slice(&record[filter_at + FILTER.len()..]);
    let page_stream_at = pdf.len();
    pdf.extend_from_slice(b"6 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n");
    let xref = pdf.len();
    writeln!(
        pdf,
        "xref\n2 1\n{replacement_at:010} 00000 n \n6 1\n{page_stream_at:010} 00000 n "
    )?;
    pdf.extend_from_slice(b"trailer\n<< /Size 9 /Root 1 0 R /Info 5 0 R /Encrypt 7 0 R ");
    pdf.extend_from_slice(file_id);
    writeln!(pdf, " /Prev {previous} >>\nstartxref\n{xref}\n%%EOF")?;
    expect_fields("R6 with explicit first Crypt filter", &pdf, b"PDF 2.0")
}

#[test]
fn embedded_stream_uses_its_file_filter_after_authentication() -> Result<(), Box<dyn Error>> {
    let locate = |bytes: &[u8], marker: &[u8]| {
        bytes
            .windows(marker.len())
            .position(|part| part == marker)
            .ok_or("expected marker in the R6 fixture")
    };
    let object_stream = &R6[locate(R6, b"2 0 obj\n")?..];
    let payload_at = locate(object_stream, b"\nstream\n")? + b"\nstream\n".len();
    let payload = &object_stream[payload_at..payload_at + 240];
    let original_security = &R6[locate(R6, b"7 0 obj\n")?..];
    let original_security =
        std::str::from_utf8(&original_security[..locate(original_security, b"\nendobj")?])?;
    let file_id = &R6[locate(R6, b"/ID [")?..];
    let file_id = &file_id[..locate(file_id, b"]")? + 1];
    let footer = &R6[locate(R6, b"startxref\n")? + b"startxref\n".len()..];
    let previous = std::str::from_utf8(&footer[..locate(footer, b"\n")?])?.parse::<u64>()?;

    for filter in ["StdCF", "Identity"] {
        let mut pdf = R6.to_vec();
        let objects = pdf.len();
        pdf.extend_from_slice(
            b"2 0 obj\n<< /Type /ObjStm /N 3 /First 15 /Length 0 \
              /F << /Type /Filespec /F (objects) /EF << /F 9 0 R >> >> \
              /FFilter /FlateDecode >>\nstream\n\nendstream\nendobj\n",
        );
        let security = pdf.len();
        let dictionary = original_security
            .replace("/AuthEvent /DocOpen", "/AuthEvent /EFOpen")
            .replace("/StmF /StdCF", &format!("/StmF /Identity /EFF /{filter}"));
        writeln!(pdf, "{dictionary}\nendobj")?;
        let embedded = pdf.len();
        writeln!(
            pdf,
            "9 0 obj\n<< /Type /EmbeddedFile /Length {} >>\nstream",
            payload.len()
        )?;
        // A revision-6 stream uses the file key directly, including after a change of object ID.
        pdf.extend_from_slice(payload);
        pdf.extend_from_slice(b"\nendstream\nendobj\n");
        let xref = pdf.len();
        writeln!(
            pdf,
            "xref\n2 1\n{objects:010} 00000 n \n7 1\n{security:010} 00000 n \n9 1\n{embedded:010} 00000 n "
        )?;
        pdf.extend_from_slice(b"trailer\n<< /Size 10 /Root 1 0 R /Info 5 0 R /Encrypt 7 0 R ");
        pdf.extend_from_slice(file_id);
        writeln!(pdf, " /Prev {previous} >>\nstartxref\n{xref}\n%%EOF")?;

        if filter == "StdCF" {
            expect_fields("R6 embedded object stream with EFF", &pdf, b"PDF 2.0")?;
        } else if extracted_fields(&pdf)? != [(FORMAT, b"PDF 2.0".to_vec())] {
            return Err("an incorrect embedded file crypt filter decoded the object stream".into());
        }
    }
    Ok(())
}

#[test]
fn locked_documents_emit_no_metadata_with_the_implicit_password() -> Result<(), Box<dyn Error>> {
    let locked = include_bytes!("fixtures/r6-locked.pdf");
    if !extracted_fields(locked)?.is_empty() {
        return Err("locked document emitted metadata".into());
    }
    Ok(())
}

#[test]
fn invalid_encryption_permissions_prevent_metadata_extraction() -> Result<(), Box<dyn Error>> {
    const PERMISSIONS: &[u8] = b"/Perms <";
    let mut pdf = R6.to_vec();
    let start = pdf
        .windows(PERMISSIONS.len())
        .position(|window| window == PERMISSIONS)
        .ok_or("permissions block missing")?;
    let first_digit = pdf
        .get_mut(start + PERMISSIONS.len())
        .ok_or("permissions block truncated")?;
    *first_digit = if *first_digit == b'0' { b'1' } else { b'0' };
    if !extracted_fields(&pdf)?.is_empty() {
        return Err("document with invalid encrypted permissions emitted metadata".into());
    }
    Ok(())
}

#[test]
fn cleartext_document_xmp_uses_its_own_standard_encryption_policy() -> Result<(), Box<dyn Error>> {
    const XML: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Quito"/></r:RDF>"#;
    let find = |data: &[u8], marker: &[u8]| {
        data.windows(marker.len())
            .position(|part| part == marker)
            .ok_or("expected marker in the R4 fixture")
    };
    let file_id = &R4[find(R4, b"/ID [")?..];
    let file_id = &file_id[..find(file_id, b"]")? + 1];
    let start = b"startxref\n";
    let footer = &R4[find(R4, start)? + start.len()..];
    let previous = std::str::from_utf8(&footer[..find(footer, b"\n")?])?.parse::<u64>()?;

    let mut pdf = R4.to_vec();
    let catalog = pdf.len();
    pdf.extend_from_slice(b"1 0 obj\n<< /Type /Catalog /Pages 3 0 R /Metadata 7 0 R >>\nendobj\n");
    let metadata = pdf.len();
    writeln!(
        pdf,
        "7 0 obj\n<< /Type /Metadata /Subtype /XML /Length {} >>\nstream",
        XML.len()
    )?;
    pdf.extend_from_slice(XML);
    pdf.extend_from_slice(b"\nendstream\nendobj\n");
    let xref = pdf.len();
    writeln!(
        pdf,
        "xref\n1 1\n{catalog:010} 00000 n \n7 1\n{metadata:010} 00000 n "
    )?;
    pdf.extend_from_slice(b"trailer\n<< /Size 8 /Root 1 0 R /Info 2 0 R /Encrypt 6 0 R ");
    pdf.extend_from_slice(file_id);
    writeln!(pdf, " /Prev {previous} >>\nstartxref\n{xref}\n%%EOF")?;

    let mut original = extracted_fields(R4)?;
    original.push((41, b"Quito".to_vec()));
    let fields = extracted_fields(&pdf)?;
    if fields != original {
        return Err(
            format!("unexpected R4 metadata with a cleartext XMP stream: {fields:?}").into(),
        );
    }
    Ok(())
}

fn expect_fields(variant: &str, pdf: &[u8], version: &[u8]) -> Result<(), Box<dyn Error>> {
    let expected: &[(u32, &[u8])] = &[
        (4, b"Guarded title"),
        (52, "星光".as_bytes()),
        (49, b"Key share"),
        (13, b"Fixture author"),
        (FORMAT, version),
        (PAGE_COUNT, b"1"),
        (58, b"2024-02-29 11:22:33"),
    ];
    let fields = extracted_fields(pdf)?;
    if !fields
        .iter()
        .map(|(kind, value)| (*kind, value.as_slice()))
        .eq(expected.iter().copied())
    {
        return Err(format!("unexpected {variant} metadata: {fields:?}").into());
    }
    Ok(())
}

fn extracted_fields(pdf: &[u8]) -> Result<Fields, &'static str> {
    let mut scratch = [0; 2_048];
    let input = Input::new(
        &pdf[..8],
        pdf.len() as u64,
        &mut scratch,
        |offset, output: &mut [u8]| {
            let start = usize::try_from(offset).map_err(|_| "PDF offset exceeds usize")?;
            let bytes = pdf
                .get(start..)
                .and_then(|tail| tail.get(..output.len()))
                .ok_or("PDF read exceeds the original extent")?;
            output.copy_from_slice(bytes);
            Ok(())
        },
    );
    let mut fields = Vec::new();
    visit(input, 128, &mut |kind, bytes| {
        fields.push((kind, bytes.to_vec()));
        Ok(())
    })?;
    Ok(fields)
}
