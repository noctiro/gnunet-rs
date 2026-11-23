use super::*;

const PIXELS: usize = 16_384;

#[test]
fn reads_ciff_metadata_in_both_orders_without_reading_image_data() -> Result<(), &'static str> {
    for order in [Order::Little, Order::Big] {
        let bytes = fixture(order, false);
        if !is_candidate(&bytes[..8]) || !detect(&bytes[..IDENTIFICATION_BYTES]) {
            return Err("CRW header was not identified");
        }
        let fields = metadata(&bytes, IDENTIFICATION_BYTES)?;
        let expected = [
            (112, b"3088x2056".as_slice()),
            (110, b"right, top"),
            (95, b"Canon"),
            (96, b"EOS 10D"),
            (58, b"2023:11:14 22:13:20"),
            (3, b"note"),
            (107, b"On"),
            (108, b"RAW"),
            (105, b"Manual (M)"),
            (104, b"100"),
            (109, b"Daylight"),
            (101, b"-0.33 EV"),
            (98, b"F4"),
            (97, b"1/128 s"),
        ];
        if !fields
            .iter()
            .map(|(kind, data)| (*kind, data.as_slice()))
            .eq(expected)
        {
            return Err("CRW metadata mismatch");
        }
    }
    Ok(())
}

#[test]
fn rejects_offsets_into_the_record_table_and_ignores_tags_in_the_wrong_role()
-> Result<(), &'static str> {
    let bytes = fixture(Order::Little, true);
    let fields = metadata(&bytes, IDENTIFICATION_BYTES)?;
    if fields.iter().any(|(kind, _)| matches!(kind, 95 | 96)) {
        return Err("invalid camera metadata escaped its heap");
    }
    if !fields
        .iter()
        .any(|(kind, value)| *kind == 112 && value == b"3088x2056")
    {
        return Err("an unrelated record hid the image dimensions");
    }
    Ok(())
}

fn metadata(bytes: &[u8], inside_prefix: usize) -> Result<Vec<(u32, Vec<u8>)>, &'static str> {
    let mut scratch = [0; 384];
    let mut metadata = Vec::new();
    visit(
        Input::new(
            &bytes[..inside_prefix],
            bytes.len() as u64,
            &mut scratch,
            |offset, destination| {
                let offset = usize::try_from(offset).map_err(|_| "invalid offset")?;
                if offset < 26 + PIXELS {
                    return Err("attempted to read raw image data");
                }
                let available = bytes
                    .get(offset..offset + destination.len())
                    .ok_or("attempted to read past file end")?;
                destination.copy_from_slice(available);
                Ok(())
            },
        ),
        64,
        &mut |kind, value| {
            metadata.push((kind, value.to_vec()));
            Ok(())
        },
    )?;
    Ok(metadata)
}

enum FixtureValue<'a> {
    External(&'a [u8]),
    Inline([u8; 8]),
    InTable,
}

fn heap(order: Order, pixels: usize, values: &[(u16, FixtureValue<'_>)]) -> Vec<u8> {
    let mut result = vec![0x69; pixels];
    let mut records = Vec::new();
    for (tag, value) in values {
        match value {
            FixtureValue::External(bytes) => {
                put_short(&mut records, order, *tag);
                put_long(&mut records, order, bytes.len() as u32);
                put_long(&mut records, order, result.len() as u32);
                result.extend_from_slice(bytes);
            }
            FixtureValue::Inline(bytes) => {
                put_short(&mut records, order, *tag | 0x4000);
                records.extend_from_slice(bytes);
            }
            FixtureValue::InTable => {
                put_short(&mut records, order, *tag);
                put_long(&mut records, order, 8);
                put_long(&mut records, order, 2);
            }
        }
    }
    let table = result.len() as u32;
    put_short(&mut result, order, values.len() as u16);
    result.extend_from_slice(&records);
    put_long(&mut result, order, table);
    result
}

fn fixture(order: Order, bad_camera: bool) -> Vec<u8> {
    let make_model = if bad_camera {
        FixtureValue::InTable
    } else {
        FixtureValue::External(b"Canon\0EOS 10D\0")
    };
    let camera = heap(order, 0, &[(0x080a, make_model)]);
    let mut shot = [0_u16; 23];
    shot[2] = 160;
    shot[7] = 1;
    shot[15] = 0xfff4;
    shot[21] = 128;
    shot[22] = 224;
    let mut settings = [0_u16; 21];
    settings[1] = 1;
    settings[3] = 4;
    settings[20] = 4;
    let exif = heap(
        order,
        0,
        &[
            (0x102d, FixtureValue::External(&words(order, settings))),
            (0x102a, FixtureValue::External(&words(order, shot))),
        ],
    );
    let mut geometry = Vec::new();
    for value in [3088, 2056, 0, 90, 8, 8, 0] {
        put_long(&mut geometry, order, value);
    }
    let mut date = Vec::new();
    put_long(&mut date, order, 1_700_000_000);
    put_long(&mut date, order, 0);
    put_long(&mut date, order, 0);
    let image = heap(
        order,
        0,
        &[
            (0x080a, FixtureValue::External(b"decoy\0camera\0")),
            (0x0805, FixtureValue::Inline(*b"note\0xyz")),
            (0x180e, FixtureValue::External(&date)),
            (0x1810, FixtureValue::External(&geometry)),
            (CAMERA_OBJECT, FixtureValue::External(&camera)),
            (EXIF_INFORMATION, FixtureValue::External(&exif)),
        ],
    );
    let mut bytes = match order {
        Order::Little => b"II".to_vec(),
        Order::Big => b"MM".to_vec(),
    };
    put_long(&mut bytes, order, 26);
    bytes.extend_from_slice(SIGNATURE);
    bytes.resize(26, 0);
    bytes.extend_from_slice(&heap(
        order,
        PIXELS,
        &[(IMAGE_PROPERTIES, FixtureValue::External(&image))],
    ));
    bytes
}

fn words<const N: usize>(order: Order, values: [u16; N]) -> Vec<u8> {
    let mut result = Vec::new();
    for value in values {
        put_short(&mut result, order, value);
    }
    result
}

fn put_short(bytes: &mut Vec<u8>, order: Order, value: u16) {
    let encoded = match order {
        Order::Little => value.to_le_bytes(),
        Order::Big => value.to_be_bytes(),
    };
    bytes.extend_from_slice(&encoded);
}

fn put_long(bytes: &mut Vec<u8>, order: Order, value: u32) {
    let encoded = match order {
        Order::Little => value.to_le_bytes(),
        Order::Big => value.to_be_bytes(),
    };
    bytes.extend_from_slice(&encoded);
}
