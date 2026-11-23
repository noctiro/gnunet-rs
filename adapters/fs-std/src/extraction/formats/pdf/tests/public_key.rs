use std::error::Error;
use std::io::Write;

use zeroize::Zeroizing;

use crate::extraction::{PdfRecipientAuthorization, PdfRecipientContent};

use super::{FORMAT, Input, PAGE_COUNT, visit};

const COPY: u32 = 0xffff_f2d0;
const DENY_COPY: u32 = 0xffff_f2c0;

type Fields = Vec<(u32, Vec<u8>)>;

#[test]
fn public_key_info_uses_its_string_filter_and_ordered_recipients() -> Result<(), Box<dyn Error>> {
    let pdf = fixture()?;
    let expected: &[(u32, &[u8])] = &[
        (4, b"Recipient metadata"),
        (FORMAT, b"PDF 1.7"),
        (PAGE_COUNT, b"1"),
        (58, b"2024-02-29 08:52:33"),
    ];
    for primary_permissions in [COPY.to_be_bytes(), COPY.to_le_bytes()] {
        let recipient = recipient(primary_permissions);
        let fields = fields(&pdf, Some(&recipient))?;
        if !fields
            .iter()
            .map(|(kind, bytes)| (*kind, bytes.as_slice()))
            .eq(expected.iter().copied())
        {
            return Err(format!("unexpected public-key PDF metadata: {fields:?}").into());
        }
    }
    Ok(())
}

#[test]
fn first_matching_public_key_recipient_can_refuse_extraction() -> Result<(), Box<dyn Error>> {
    let pdf = fixture()?;
    for primary_permissions in [DENY_COPY.to_be_bytes(), DENY_COPY.to_le_bytes()] {
        let denied = recipient(primary_permissions);
        if !fields(&pdf, Some(&denied))?.is_empty() {
            return Err("the alternate recipient overrode the first matching permissions".into());
        }
    }
    if !fields(&pdf, None)?.is_empty() {
        return Err("public-key PDF metadata was emitted without recipient authorization".into());
    }
    Ok(())
}

#[test]
fn attachment_only_public_key_protection_keeps_clear_metadata_readable()
-> Result<(), Box<dyn Error>> {
    let pdf = document(
        "<< /Title (Clear metadata) >>",
        "<< /Filter /Adobe.PubSec /SubFilter /adbe.pkcs7.s5 /V 4 \
         /StmF /Identity /StrF /Identity /EFF /DefEmbeddedFile \
         /CF << /DefEmbeddedFile << /CFM /AESV2 /Length 128 /AuthEvent /EFOpen \
         /Recipients (attachment:recipient) >> >> >>",
    )?;
    if !fields(&pdf, None)?
        .iter()
        .any(|(kind, bytes)| *kind == 4 && bytes == b"Clear metadata")
    {
        return Err("the attachment filter suppressed clear document metadata".into());
    }
    Ok(())
}

fn recipient(primary_permissions: [u8; 4]) -> PdfRecipientAuthorization {
    PdfRecipientAuthorization::new([0x42; 32], move |der| {
        let (seed, permissions) = match der {
            b"stream:key" => ([0x41; 20], COPY.to_be_bytes()),
            b"string:primary" => (
                std::array::from_fn(|index| index as u8),
                primary_permissions,
            ),
            b"string:alternate" => (std::array::from_fn(|index| index as u8), COPY.to_be_bytes()),
            _ => return None,
        };
        Some(PdfRecipientContent::Document {
            seed: Zeroizing::new(seed),
            permissions,
        })
    })
}

fn fixture() -> Result<Vec<u8>, std::io::Error> {
    // The fixed ciphertext uses SHA-1 file key ebd2f4ee625ad83b4b0e059aef284210
    // and the RC4 key c99757a1b73d9aacd861c667207e017b for object 3, generation 2.
    const INFO: &str = "<< /Title <3930c4d22e215451c75c0b26fce0cc5731f3> \
        /CreationDate <2f6f958b6c7c010d81455772bab39b056ea28d7c50dfa9> >>";
    const ENCRYPT: &str = r"<< /Filter /Adobe.PubSec /SubFilter /adbe.pkcs7.s5 /V 4
        /StmF /Streams /StrF /Strings
        /CF << /Streams << /CFM /V2 /Length 128 /Recipients [(stream:key)] >>
        /Strings << /CFM /V2 /Length 128
        /Recipients [(unselected\000group) <737472696e673a7072696d617279> (string:alternate)] >> >> >>";
    document(INFO, ENCRYPT)
}

fn document(info: &str, encrypt: &str) -> Result<Vec<u8>, std::io::Error> {
    let mut pdf = b"%PDF-1.7\n%\x80\x81\x82\x83\n".to_vec();
    let mut entries = Vec::new();
    for (index, (generation, body)) in [
        (0, "<< /Type /Catalog /Pages 2 0 R >>"),
        (0, "<< /Type /Pages /Kids [5 0 R] /Count 1 >>"),
        (2, info),
        (0, encrypt),
        (0, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 210 297] >>"),
    ]
    .into_iter()
    .enumerate()
    {
        entries.push((pdf.len(), generation));
        writeln!(pdf, "{} {generation} obj\n{body}\nendobj", index + 1)?;
    }
    let xref = pdf.len();
    writeln!(pdf, "xref\n0 6\n0000000000 65535 f ")?;
    for (offset, generation) in entries {
        writeln!(pdf, "{offset:010} {generation:05} n ")?;
    }
    writeln!(
        pdf,
        "trailer\n<< /Size 6 /Root 1 0 R /Info 3 2 R /Encrypt 4 0 R \
         /ID [<1db972df8552549691b11e31548b97f6> <1db972df8552549691b11e31548b97f6>] >>\n\
         startxref\n{xref}\n%%EOF"
    )?;
    Ok(pdf)
}

fn fields(
    pdf: &[u8],
    recipient: Option<&PdfRecipientAuthorization>,
) -> Result<Fields, &'static str> {
    let input = Input::new(pdf, pdf.len() as u64, &mut [], |_, _: &mut [u8]| {
        Err("unexpected positioned read")
    })
    .with_pdf_authorization(None, recipient);
    let mut fields = Vec::new();
    visit(input, 128, &mut |kind, bytes| {
        fields.push((kind, bytes.to_vec()));
        Ok(())
    })?;
    Ok(fields)
}
