use std::error::Error;
use std::io::Write;

use gnunet_fs::metadata::Deflater;
use gnunet_fs_codec::Compressor;

use super::{FORMAT, Input, PAGE_COUNT, visit};

mod encrypted;
mod external;
mod public_key;

#[test]
fn compressed_xref_resolves_catalog_info_and_pages_in_one_object_stream()
-> Result<(), Box<dyn Error>> {
    check_object_stream_fixture(StructuralFilters::Flate)
}

#[test]
fn cross_reference_filters_apply_in_order_with_per_filter_parameters() -> Result<(), Box<dyn Error>>
{
    check_object_stream_fixture(StructuralFilters::Ascii85FlateAndRunLength)
}

#[derive(Clone, Copy)]
enum StructuralFilters {
    Flate,
    Ascii85FlateAndRunLength,
}

fn check_object_stream_fixture(filters: StructuralFilters) -> Result<(), Box<dyn Error>> {
    const OBJECTS_AT: usize = 8_192;
    let mut file = b"%PDF-1.7\n%\x80\x81\x82\x83\n".to_vec();
    file.resize(OBJECTS_AT, b'\n');

    let page = file.len() as u32;
    file.extend_from_slice(
        b"6 0 obj\n<< /Type /Page /Parent 3 0 R /MediaBox [0 0 210 297] >>\nendobj\n",
    );
    let objects = file.len() as u32;
    let catalog = b"<< /Type /Catalog /Pages 3 0 R >>";
    let info_prefix = b"<< /Title (Shared stream) /Author (R. Example) /Subject (";
    let info_suffix = b") >>";
    // A second expansion would exhaust the budget. The optional subject
    // also exceeds the field limit, so only the intended values are emitted.
    let subject = [b'a'; 1_600];
    let pages = b"<< /Type /Pages /Kids [6 0 R] /Count 1 >>";
    let header = format!(
        "1 0 2 {} 3 {} ",
        catalog.len(),
        catalog.len() + info_prefix.len() + subject.len() + info_suffix.len()
    );
    let segments = [
        header.as_bytes(),
        catalog,
        info_prefix,
        &subject,
        info_suffix,
        pages,
    ];
    let (object_filter, compressed_objects) = match filters {
        StructuralFilters::Flate => ("/FlateDecode", zlib(&segments.concat())?),
        StructuralFilters::Ascii85FlateAndRunLength => ("/RunLengthDecode", run_length(&segments)),
    };
    writeln!(
        file,
        "4 0 obj\n<< /Type /ObjStm /N 3 /First {} /Filter {object_filter} /Length {} >>\nstream",
        header.len(),
        compressed_objects.len(),
    )?;
    file.extend_from_slice(&compressed_objects);
    file.extend_from_slice(b"\nendstream\nendobj\n");

    let xref = file.len() as u32;
    let rows = [
        xref_row(0, 0, 65_535),
        xref_row(2, 4, 0),
        xref_row(2, 4, 1),
        xref_row(2, 4, 2),
        xref_row(1, objects, 0),
        xref_row(1, xref, 0),
        xref_row(1, page, 0),
    ];
    let mut previous = [0_u8; 7];
    let mut predicted = Vec::new();
    for row in rows {
        predicted.push(2); // PNG Up prediction encodes one tag per row.
        predicted.extend(
            row.iter()
                .zip(previous)
                .map(|(&at, before)| at.wrapping_sub(before)),
        );
        previous = row;
    }
    let compressed_xref = zlib(&predicted)?;
    let (xref_filters, params, xref_data) = match filters {
        StructuralFilters::Flate => (
            "/FlateDecode",
            "<< /Predictor 12 /Columns 7 >>",
            compressed_xref,
        ),
        StructuralFilters::Ascii85FlateAndRunLength => (
            "[/ASCII85Decode /FlateDecode]",
            "[null << /Predictor 12 /Columns 7 >>]",
            ascii85(&compressed_xref),
        ),
    };
    writeln!(
        file,
        "5 0 obj\n<< /Type /XRef /Size 7 /W [1 4 2] /Root 1 0 R /Info 2 0 R \
         /Filter {xref_filters} /DecodeParms {params} /Length {} >>\nstream",
        xref_data.len(),
    )?;
    file.extend_from_slice(&xref_data);
    writeln!(file, "\nendstream\nendobj\nstartxref\n{xref}\n%%EOF")?;

    let mut scratch = [0_u8; 576];
    let input = Input::new(
        &file[..8],
        file.len() as u64,
        &mut scratch,
        |offset, output: &mut [u8]| {
            let offset = usize::try_from(offset).map_err(|_| "fixture offset exceeds usize")?;
            if offset < OBJECTS_AT {
                return Err("unexpected read before the selected objects");
            }
            output.copy_from_slice(&file[offset..offset + output.len()]);
            Ok(())
        },
    );
    let mut fields = Vec::new();
    visit(input, 128, &mut |kind, bytes| {
        fields.push((kind, bytes.to_vec()));
        Ok(())
    })?;
    let expected = [
        (4, b"Shared stream".to_vec()),
        (13, b"R. Example".to_vec()),
        (FORMAT, b"PDF 1.7".to_vec()),
        (PAGE_COUNT, b"1".to_vec()),
    ];
    if fields != expected {
        return Err(format!("unexpected PDF fields: {fields:?}").into());
    }
    Ok(())
}

#[test]
fn a_later_revision_uses_its_direct_info_and_blocks_stale_generations() -> Result<(), Box<dyn Error>>
{
    let mut base = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (index, body) in [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [] /Count 0 >>",
        "<< /Title (Earlier title) >>",
    ]
    .into_iter()
    .enumerate()
    {
        offsets.push(base.len());
        writeln!(base, "{} 0 obj\n{body}\nendobj", index + 1)?;
    }
    let previous = base.len();
    writeln!(base, "xref\n0 4\n0000000000 65535 f ")?;
    for offset in offsets {
        writeln!(base, "{offset:010} 00000 n ")?;
    }
    writeln!(
        base,
        "trailer\n<< /Size 4 /Root 1 0 R /Info 3 0 R >>\nstartxref\n{previous}\n%%EOF"
    )?;
    let later_info = base.len();
    writeln!(base, "3 1 obj\n(New subject)\nendobj")?;
    let latest = base.len();
    writeln!(base, "xref\n3 1\n{later_info:010} 00001 n ")?;

    for (info, expected) in [
        (
            "<< /Title <FEFF661F5149> /Subject 3 1 R >>",
            Some(("星光", "New subject")),
        ),
        ("3 0 R", None),
    ] {
        let mut file = base.clone();
        writeln!(
            file,
            "trailer\n<< /Size 4 /Root 1 0 R /Prev {previous} /Info {info} >>\nstartxref\n{latest}\n%%EOF"
        )?;
        let input = Input::new(&file, file.len() as u64, &mut [], |_, _: &mut [u8]| {
            Err("unexpected positioned read")
        });
        let mut titles_and_subjects = Vec::new();
        visit(input, 128, &mut |kind, bytes| {
            if matches!(kind, 4 | 52) {
                titles_and_subjects.push((kind, bytes.to_vec()));
            }
            Ok(())
        })?;
        let expected = expected
            .map(|(title, subject)| {
                [
                    (4, title.as_bytes().to_vec()),
                    (52, subject.as_bytes().to_vec()),
                ]
            })
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        if titles_and_subjects != expected {
            return Err(format!(
                "unexpected fields in the later revision: {titles_and_subjects:?}"
            )
            .into());
        }
    }
    Ok(())
}

#[test]
fn a_hybrid_update_blocks_deleted_info_and_resolves_objects_missing_from_its_table()
-> Result<(), Box<dyn Error>> {
    let mut file = b"%PDF-1.7\n%\x80\x81\x82\x83\n".to_vec();
    let mut offsets = [0; 7];
    for (number, body) in [
        (1, "<< /Type /Catalog /Pages 2 0 R >>"),
        (2, "<< /Type /Pages /Kids [6 0 R] /Count 1 >>"),
        (3, "<< /Title 4 0 R /Author 5 0 R >>"),
        (4, "(Earlier title)"),
        (6, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 210 297] >>"),
    ] {
        offsets[number] = file.len();
        writeln!(file, "{number} 0 obj\n{body}\nendobj")?;
    }
    let previous = file.len();
    writeln!(file, "xref\n0 7\n0000000005 65535 f ")?;
    for offset in &offsets[1..5] {
        writeln!(file, "{offset:010} 00000 n ")?;
    }
    writeln!(file, "0000000000 65535 f \n{:010} 00000 n ", offsets[6])?;
    writeln!(
        file,
        "trailer\n<< /Size 7 /Root 1 0 R /Info 3 0 R >>\nstartxref\n{previous}\n%%EOF"
    )?;

    let objects = file.len();
    let stale = b"(Stale title)";
    let author = b"(New author)";
    let header = format!("4 0 5 {} ", stale.len());
    let length = header.len() + stale.len() + author.len();
    writeln!(
        file,
        "7 0 obj\n<< /Type /ObjStm /N 2 /First {} /Length {length} >>\nstream",
        header.len()
    )?;
    file.extend_from_slice(header.as_bytes());
    file.extend_from_slice(stale);
    file.extend_from_slice(author);
    file.extend_from_slice(b"\nendstream\nendobj\n");
    let supplement = file.len();
    writeln!(
        file,
        "8 0 obj\n<< /Type /XRef /Size 9 /Index [4 2] /W [1 4 2] /Length 14 >>\nstream"
    )?;
    file.extend_from_slice(&xref_row(2, 7, 0));
    file.extend_from_slice(&xref_row(2, 7, 1));
    file.extend_from_slice(b"\nendstream\nendobj\n");

    let latest = file.len();
    writeln!(
        file,
        "xref\n0 1\n0000000004 65535 f \n4 1\n0000000005 00001 f \n7 2\n{objects:010} 00000 n \n{supplement:010} 00000 n "
    )?;
    writeln!(
        file,
        "trailer\n<< /Size 9 /Root 1 0 R /Info 3 0 R /Prev {previous} /XRefStm {supplement} >>\nstartxref\n{latest}\n%%EOF"
    )?;

    let input = Input::new(&file, file.len() as u64, &mut [], |_, _: &mut [u8]| {
        Err("unexpected positioned read")
    });
    let mut fields = Vec::new();
    visit(input, 128, &mut |kind, bytes| {
        if matches!(kind, 4 | 13) {
            fields.push((kind, bytes.to_vec()));
        }
        Ok(())
    })?;
    if fields != [(13, b"New author".to_vec())] {
        return Err(format!("unexpected hybrid PDF fields: {fields:?}").into());
    }
    Ok(())
}

#[test]
fn object_stream_settings_resolve_uncompressed_references_in_the_current_generation()
-> Result<(), Box<dyn Error>> {
    const PARAMETERS_AT: usize = 8_192;
    const DOCUMENT_AT: usize = 32_768;
    const FILTER_GENERATION: u16 = 2;
    let index = b"4 0 ";
    let info = b"<< /Title (Indirect settings) /Author (R. Example) >>";
    let predicted = [b"\x02".as_slice(), index.as_slice(), info.as_slice()].concat();
    let encoded = ascii85(&zlib(&predicted)?);

    for filter_reference in [FILTER_GENERATION, FILTER_GENERATION - 1] {
        let mut file = b"%PDF-2.0\n%\x80\x81\x82\x83\n".to_vec();
        let mut rows = [xref_row(0, 0, 65_535); 17];
        file.resize(PARAMETERS_AT, b'\n');
        for (number, generation, body) in [
            (6, 0, "1".to_owned()),
            (7, 0, index.len().to_string()),
            (8, 0, encoded.len().to_string()),
            (9, 0, format!("[12 {filter_reference} R /FlateDecode]")),
            (10, 0, "[null 13 0 R]".to_owned()),
            (11, 0, "/ObjStm".to_owned()),
            (12, FILTER_GENERATION, "/ASCII85Decode".to_owned()),
            (13, 0, "<< /Predictor 14 0 R /Columns 15 0 R >>".to_owned()),
            (14, 0, "12".to_owned()),
            (15, 0, (index.len() + info.len()).to_string()),
        ] {
            rows[number] = xref_row(1, file.len() as u32, generation);
            writeln!(file, "{number} {generation} obj\n{body}\nendobj")?;
        }
        let parameters_end = file.len();
        file.resize(DOCUMENT_AT, b'\n');
        for (number, body) in [
            (1, "<< /Type /Catalog /Pages 2 0 R >>"),
            (2, "<< /Type /Pages /Kids [5 0 R] /Count 1 >>"),
            (
                5,
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 210 297] /Resources <<>> >>",
            ),
        ] {
            rows[number] = xref_row(1, file.len() as u32, 0);
            writeln!(file, "{number} 0 obj\n{body}\nendobj")?;
        }
        rows[3] = xref_row(1, file.len() as u32, 0);
        rows[4] = xref_row(2, 3, 0);
        file.extend_from_slice(
            b"3 0 obj\n<< /Type 11 0 R /N 6 0 R /First 7 0 R /Length 8 0 R \
              /Filter 9 0 R /DecodeParms 10 0 R >>\nstream\n",
        );
        file.extend_from_slice(&encoded);
        file.extend_from_slice(b"\nendstream\nendobj\n");

        let xref = file.len();
        rows[16] = xref_row(1, xref as u32, 0);
        let xref_data = rows.as_flattened();
        writeln!(
            file,
            "16 0 obj\n<< /Type /XRef /Size 17 /W [1 4 2] /Root 1 0 R /Info 4 0 R /Length {} >>\nstream",
            xref_data.len(),
        )?;
        file.extend_from_slice(xref_data);
        writeln!(file, "\nendstream\nendobj\nstartxref\n{xref}\n%%EOF")?;

        let mut scratch = [0_u8; 1_536];
        let input = Input::new(
            &file[..8],
            file.len() as u64,
            &mut scratch,
            |offset, output: &mut [u8]| {
                let offset = usize::try_from(offset).map_err(|_| "fixture offset exceeds usize")?;
                let end = offset + output.len();
                // Allow read-ahead around the parameter objects while keeping both gaps out of the probe.
                if offset < DOCUMENT_AT && (offset < PARAMETERS_AT || end > parameters_end + 256) {
                    return Err("unexpected read in the gaps between PDF objects");
                }
                output.copy_from_slice(&file[offset..end]);
                Ok(())
            },
        );
        let mut fields = Vec::new();
        visit(input, 128, &mut |kind, bytes| {
            fields.push((kind, bytes.to_vec()));
            Ok(())
        })?;

        let mut expected = Vec::new();
        if filter_reference == FILTER_GENERATION {
            expected.extend([
                (4, b"Indirect settings".to_vec()),
                (13, b"R. Example".to_vec()),
            ]);
        }
        expected.extend([(FORMAT, b"PDF 2.0".to_vec()), (PAGE_COUNT, b"1".to_vec())]);
        if fields != expected {
            return Err(format!(
                "unexpected fields for filter generation {filter_reference}: {fields:?}"
            )
            .into());
        }
    }
    Ok(())
}

fn xref_row(kind: u8, position: u32, index: u16) -> [u8; 7] {
    let mut row = [kind, 0, 0, 0, 0, 0, 0];
    row[1..5].copy_from_slice(&position.to_be_bytes());
    row[5..7].copy_from_slice(&index.to_be_bytes());
    row
}

fn zlib(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = vec![0; data.len() + 32];
    let result = Compressor::new()
        .deflate(data, &mut output)
        .map_err(|error| format!("could not compress PDF fixture: {error:?}"))?;
    output.truncate(result.produced);
    Ok(output)
}

fn ascii85(data: &[u8]) -> Vec<u8> {
    let mut output = Vec::new();
    for group in data.chunks(4) {
        let mut bytes = [0; 4];
        bytes[..group.len()].copy_from_slice(group);
        let mut word = u32::from_be_bytes(bytes);
        let mut digits = [0; 5];
        for digit in digits.iter_mut().rev() {
            *digit = b'!' + (word % 85) as u8;
            word /= 85;
        }
        output.extend_from_slice(&digits[..group.len() + 1]);
    }
    output.extend_from_slice(b"~>");
    output
}

fn run_length(segments: &[&[u8]]) -> Vec<u8> {
    let mut output = Vec::new();
    for chunk in segments.iter().flat_map(|segment| segment.chunks(128)) {
        if let [first, tail @ ..] = chunk
            && !tail.is_empty()
            && tail.iter().all(|byte| byte == first)
        {
            output.extend_from_slice(&[(257 - chunk.len()) as u8, *first]);
        } else {
            output.push((chunk.len() - 1) as u8);
            output.extend_from_slice(chunk);
        }
    }
    output.push(128);
    output
}
