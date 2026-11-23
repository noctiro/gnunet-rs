use super::{ascii85, run_length, xref_row, zlib};
use crate::extraction::formats::pdf::{FORMAT, Input, PAGE_COUNT, visit};
use std::error::Error;
use std::io::Write;

#[test]
fn resolves_document_owned_external_streams_without_using_the_inline_data()
-> Result<(), Box<dyn Error>> {
    let xml = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Quito"/></r:RDF>"#;
    let decoy = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Paris"/></r:RDF>"#;
    let predicted = [&[2u8], xml.as_slice()].concat();
    let embedded = run_length(&[&ascii85(&zlib(&predicted)?)]);
    let objects = zlib(b"8 0 << /Title (Embedded objects) >>")?;
    for scenario in [
        "embedded",
        "unbound",
        "wrong length",
        "nested",
        "external xref",
    ] {
        let mut file = b"%PDF-2.0\n".to_vec();
        let mut rows = [xref_row(0, 0, 65_535); 12];
        for (id, contents) in [
            (
                1,
                "<< /Type /Catalog /Pages 2 0 R /Metadata 3 0 R >>".into(),
            ),
            (2, "<< /Type /Pages /Count 1 >>".into()),
            (
                4,
                "<< /Type /Filespec /F (metadata) /UF (metadata) /EF << /F 7 0 R /UF 5 0 R >> >>"
                    .into(),
            ),
            (10, "[/ASCII85Decode /FlateDecode]".into()),
            (
                11,
                format!("[null << /Predictor 12 /Columns {} >>]", xml.len()),
            ),
        ] {
            rows[id] = xref_row(1, file.len() as u32, 0);
            writeln!(file, "{id} 0 obj\n{contents}\nendobj")?;
        }
        rows[3] = xref_row(1, file.len() as u32, 0);
        let filespec = if scenario == "unbound" {
            "(metadata)"
        } else {
            "4 0 R"
        };
        let length = if scenario == "wrong length" {
            decoy.len() + 2
        } else {
            decoy.len()
        };
        writeln!(
            file,
            "3 0 obj\n<< /Type /Metadata /Subtype /XML /Length {length} /F {filespec} \
             /Filter /DCTDecode /FFilter 10 0 R /FDecodeParms 11 0 R >>\nstream"
        )?;
        file.extend_from_slice(decoy);
        file.extend_from_slice(b"\nendstream\nendobj\n");

        rows[5] = xref_row(1, file.len() as u32, 0);
        let nested = if scenario == "nested" {
            "/F << /Type /Filespec /F (metadata) /EF << /F 3 0 R >> >>"
        } else {
            ""
        };
        writeln!(
            file,
            "5 0 obj\n<< /Length {} /Filter /RunLengthDecode {nested} >>\nstream",
            embedded.len()
        )?;
        file.extend_from_slice(&embedded);
        file.extend_from_slice(b"\nendstream\nendobj\n");

        rows[6] = xref_row(1, file.len() as u32, 0);
        file.extend_from_slice(
            b"6 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length 0 \
              /F << /Type /Filespec /F (objects) /EF << /F 7 0 R >> >> \
              /FFilter /FlateDecode >>\nstream\n\nendstream\nendobj\n",
        );
        rows[7] = xref_row(1, file.len() as u32, 0);
        writeln!(
            file,
            "7 0 obj\n<< /Type /EmbeddedFile /Length {} >>\nstream",
            objects.len()
        )?;
        file.extend_from_slice(&objects);
        file.extend_from_slice(b"\nendstream\nendobj\n");
        rows[8] = xref_row(2, 6, 0);

        let xref = file.len();
        rows[9] = xref_row(1, xref as u32, 0);
        let xref_data = rows.as_flattened();
        let xref_source = if scenario == "external xref" {
            "/F (xref)"
        } else {
            ""
        };
        writeln!(
            file,
            "9 0 obj\n<< /Type /XRef /Size 12 /W [1 4 2] /Root 1 0 R /Info 8 0 R \
             /Length {} {xref_source} >>\nstream",
            xref_data.len(),
        )?;
        file.extend_from_slice(xref_data);
        writeln!(file, "\nendstream\nendobj\nstartxref\n{xref}\n%%EOF")?;

        let fields = fixture_fields(&file)?;
        let mut expected = Vec::new();
        if scenario != "external xref" {
            expected.extend([
                (4, b"Embedded objects".to_vec()),
                (FORMAT, b"PDF 2.0".to_vec()),
                (PAGE_COUNT, b"1".to_vec()),
            ]);
        }
        if scenario == "embedded" {
            expected.push((41, b"Quito".to_vec()));
        }
        if fields != expected {
            return Err(format!("unexpected PDF fields for {scenario}: {fields:?}").into());
        }
    }
    Ok(())
}

#[test]
fn metadata_resolves_compressed_stream_controls_without_allowing_bootstrap_cycles()
-> Result<(), Box<dyn Error>> {
    let xml = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Quito"/></r:RDF>"#;
    let predicted = [&[2u8], xml.as_slice()].concat();
    let encoded = zlib(&predicted)?;
    for (embedded, cyclic) in [(false, false), (true, false), (true, true)] {
        let mut file = b"%PDF-2.0\n".to_vec();
        let mut rows = [xref_row(0, 0, 65_535); 13];
        for (id, contents) in [
            (1, "<< /Type /Catalog /Pages 2 0 R /Metadata 3 0 R >>"),
            (2, "<< /Type /Pages /Count 1 >>"),
        ] {
            rows[id] = xref_row(1, file.len() as u32, 0);
            writeln!(file, "{id} 0 obj\n{contents}\nendobj")?;
        }
        let (metadata_parameters, inline_bytes) = if embedded {
            ("/F 8 0 R /FFilter 6 0 R /FDecodeParms 7 0 R", [].as_slice())
        } else {
            ("/Filter 6 0 R /DecodeParms 7 0 R", encoded.as_slice())
        };
        rows[3] = xref_row(1, file.len() as u32, 0);
        writeln!(
            file,
            "3 0 obj\n<< /Type /Metadata /Subtype /XML /Length 5 0 R {metadata_parameters} >>\nstream"
        )?;
        file.extend_from_slice(inline_bytes);
        file.extend_from_slice(b"\nendstream\nendobj\n");

        let parameters = [
            (5, inline_bytes.len().to_string()),
            (6, "/FlateDecode".into()),
            (7, format!("<< /Predictor 12 /Columns {} >>", xml.len())),
            (
                8,
                "<< /Type /Filespec /F (metadata) /EF << /F 10 0 R >> >>".into(),
            ),
            (9, "6".into()),
            (12, encoded.len().to_string()),
        ];
        let mut directory = Vec::new();
        let mut objects = Vec::new();
        for (index, (number, value)) in parameters.into_iter().enumerate() {
            rows[number] = xref_row(2, 4, index as u16);
            write!(directory, "{number} {} ", objects.len())?;
            write!(objects, "{value} ")?;
        }
        let first = directory.len();
        directory.extend_from_slice(&objects);
        let object_data = zlib(&directory)?;
        let count = if cyclic { "9 0 R" } else { "6" };
        rows[4] = xref_row(1, file.len() as u32, 0);
        writeln!(
            file,
            "4 0 obj\n<< /Type /ObjStm /Filter /FlateDecode /First {first} /N {count} /Length {} >>\nstream",
            object_data.len()
        )?;
        file.extend_from_slice(&object_data);
        file.extend_from_slice(b"\nendstream\nendobj\n");

        if embedded {
            rows[10] = xref_row(1, file.len() as u32, 0);
            file.extend_from_slice(b"10 0 obj\n<< /Type /EmbeddedFile /Length 12 0 R >>\nstream\n");
            file.extend_from_slice(&encoded);
            file.extend_from_slice(b"\nendstream\nendobj\n");
        }
        let xref = file.len();
        rows[11] = xref_row(1, xref as u32, 0);
        let xref_data = rows.as_flattened();
        writeln!(
            file,
            "11 0 obj\n<< /Type /XRef /Size 13 /W [1 4 2] /Root 1 0 R /Length {} >>\nstream",
            xref_data.len()
        )?;
        file.extend_from_slice(xref_data);
        writeln!(file, "\nendstream\nendobj\nstartxref\n{xref}\n%%EOF")?;

        let mut expected = vec![(FORMAT, b"PDF 2.0".to_vec()), (PAGE_COUNT, b"1".to_vec())];
        if !cyclic {
            expected.push((41, b"Quito".to_vec()));
        }
        let fields = fixture_fields(&file)?;
        if fields != expected {
            return Err(format!(
                "unexpected fields for embedded={embedded}, cyclic={cyclic}: {fields:?}"
            )
            .into());
        }
    }
    Ok(())
}

fn fixture_fields(file: &[u8]) -> Result<Vec<(u32, Vec<u8>)>, &'static str> {
    let mut fields = Vec::new();
    let mut scratch = [0; 4096];
    let input = Input::new(
        &file[..8],
        file.len() as u64,
        &mut scratch,
        |at, bytes: &mut [u8]| {
            let start = usize::try_from(at).map_err(|_| "fixture offset exceeds usize")?;
            bytes.copy_from_slice(&file[start..start + bytes.len()]);
            Ok(())
        },
    );
    visit(input, 128, &mut |key, value| {
        fields.push((key, value.to_vec()));
        Ok(())
    })?;
    Ok(fields)
}
