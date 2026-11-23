//! Actual local descriptor/probe/sink boundaries; no provider or publication is
//! replaced with a success receipt and no service connection is constructed.
#![expect(
    clippy::panic_in_result_fn,
    reason = "Assertions identify actual local descriptor fixture failures; filesystem and host errors remain returned to the test harness."
)]
use super::*;
use std::fs::{self, OpenOptions};
use std::{
    error::Error as StdError,
    io::{Seek, Write},
    sync::atomic::{AtomicU64, Ordering},
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Result<Self, Box<dyn StdError>> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "gnunet-fs-inspect-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let parent = gnunet_native::filesystem::Directory::open(&std::env::temp_dir())?;
        let name = path
            .file_name()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        drop(parent.create_private_directory(name)?);
        Ok(Self(path))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _cleanup = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn id3_tail_follows_the_detected_media_family() -> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let mut tail = [0; 128];
    tail[..13].copy_from_slice(b"TAGTail title");
    let policy = Policy::default();
    for (name, header, expected) in [
        ("image.gif", b"GIF87a\x01\0\x01\0\0\0\0;".as_slice(), false),
        ("audio.mp3", b"ID3\x03\0\0\0\0\0\0".as_slice(), true),
    ] {
        let path = directory.0.join(name);
        fs::write(&path, [header, &tail].concat())?;
        inspect_with_metadata(
            &path,
            Limits::default(),
            policy,
            MetadataSettings::default(),
            |_| Control::Continue,
            |object| {
                let metadata = decoded(&object.metadata, policy)?;
                assert_eq!(
                    metadata
                        .items()
                        .any(|item| item.kind == 4 && item.text() == Some(b"Tail title")),
                    expected
                );
                Ok(())
            },
        )?;
    }
    Ok(())
}

#[test]
fn trimmed_preview_copies_metadata_but_moves_majority_keywords() -> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    for (filename, title) in [
        ("a.html", "Common phrase"),
        ("b.html", "Common phrase"),
        ("c.html", "Individual text"),
    ] {
        fs::write(
            directory.0.join(filename),
            format!("<html><title>{title}</title></html>"),
        )?;
    }
    let mut manual = ManualMetadata::default();
    manual.push(b"title:Explicit root")?;
    let settings = MetadataSettings::default().with_manual(manual);
    let mut rows = Vec::new();
    let policy = Policy::default();
    let report = inspect_trimmed(
        &directory.0,
        Limits::default(),
        policy,
        settings,
        Some(b"Publication date fixture"),
        |_| Control::Continue,
        |object| {
            let metadata = decoded(&object.metadata, policy)?;
            let contains = |kind, value: &[u8]| {
                metadata
                    .items()
                    .any(|item| item.kind == kind && item.text() == Some(value))
            };
            rows.push((
                object.relative.clone(),
                contains(4, b"Common phrase"),
                contains(4, b"Explicit root"),
                contains(24, b"Publication date fixture"),
                object.keywords,
            ));
            Ok(())
        },
        |_| Ok(()),
    )?;
    assert_eq!(report.objects, 4);
    let [root, a, b, c] = rows.as_slice() else {
        return Err("unexpected trimmed object order".into());
    };
    assert!(root.0.as_os_str().is_empty() && root.1 && root.2 && root.3);
    assert!(root.4.iter().any(|term| term == b"common phrase"));
    assert!(root.4.iter().any(|term| term == gnunet_fs::directory::MIME));
    for item in [a, b] {
        assert!(item.1 && !item.2 && item.3);
        assert!(!item.4.iter().any(|term| term == b"common phrase"));
    }
    assert!(!c.1 && !c.2 && c.3);
    assert!(c.4.iter().any(|term| term == b"individual text"));
    Ok(())
}

#[test]
fn sparse_file_uses_shared_metadata_and_terms_without_payload_artifacts()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let path = directory.0.join("Archive Title.html");
    let root = gnunet_native::filesystem::Directory::open(&directory.0)?;
    let mut input = root.create_private_file(std::ffi::OsStr::new("Archive Title.html"))?;
    input.write_all(b"<html><title>Actual title</title></html>")?;
    input.set_len(1024 * 1024 * 1024)?;
    input.seek(std::io::SeekFrom::Start(17))?;
    let policy = Policy {
        max_probe_bytes: 64,
        ..Default::default()
    };
    let expected = file_keywords(&input, &path, policy, |_| Control::Continue)?;
    let mut extracted = None;
    let report = inspect_with_metadata(
        &path,
        Limits::default(),
        policy,
        MetadataSettings::default(),
        |_| Control::Continue,
        |object| {
            extracted = Some(object);
            Ok(())
        },
    )?;
    let extracted = extracted.ok_or("missing extraction")?;
    assert_eq!(extracted.keywords, expected);
    assert!(
        decoded(&extracted.metadata, policy)?
            .items()
            .any(|item| item.kind == 4 && item.text() == Some(b"Actual title"))
    );
    assert_eq!(report.source_bytes, 1024 * 1024 * 1024);
    assert_eq!(report.objects, 1);
    assert_eq!(input.stream_position()?, 17);
    assert_eq!(fs::read_dir(&directory.0)?.count(), 1);
    Ok(())
}

#[test]
fn png_text_after_image_data_uses_the_original_file_probe_budget() -> Result<(), Box<dyn StdError>>
{
    let directory = Directory::new()?;
    let path = directory.0.join("image.png");
    let mut image =
        b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR\0\0\0\x01\0\0\0\x01\x08\x06\0\0\0\x1f\x15\xc4\x89"
            .to_vec();
    image.extend_from_slice(b"\0\0\x20\0vpAg");
    image.resize(image.len() + 8192, 0);
    image.extend_from_slice(&0x6929_d514_u32.to_be_bytes());
    image.extend_from_slice(b"\0\0\0\x0bIDAT\x78\x9c\x63\x60\0\x02\0\0\x05\0\x01\x7a\x5e\xab\x3f");
    image.extend_from_slice(b"\0\0\0\x11tEXtTitle\0Disk footer\x87\x1a\x49\xca");
    image.extend_from_slice(b"\0\0\0\0IEND\xae\x42\x60\x82");
    fs::write(&path, &image)?;
    let policy = Policy {
        max_probe_bytes: 96,
        ..Default::default()
    };
    let mut found = false;
    let report = inspect_with_metadata(
        &path,
        Limits::default(),
        policy,
        MetadataSettings::default(),
        |_| Control::Continue,
        |object| {
            found = decoded(&object.metadata, policy)?
                .items()
                .any(|item| item.kind == 4 && item.text() == Some(b"Disk footer"));
            Ok(())
        },
    )?;
    assert!(found);
    assert_eq!(report.source_bytes, image.len() as u64);
    Ok(())
}

#[test]
fn webp_publishes_an_exact_binary_profile_and_exif_from_the_held_descriptor()
-> Result<(), Box<dyn StdError>> {
    fn append(webp: &mut Vec<u8>, kind: &[u8; 4], bytes: &[u8]) {
        webp.extend_from_slice(kind);
        webp.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        webp.extend_from_slice(bytes);
        webp.resize(webp.len().next_multiple_of(2), 0);
    }

    let directory = Directory::new()?;
    let profile = formats::icc::fixture();
    let path = directory.0.join("Color.webp");
    for (valid, allowed) in [(true, true), (false, true), (true, false)] {
        let mut webp = b"RIFF\0\0\0\0WEBP".to_vec();
        append(&mut webp, b"VP8X", b"\x28\0\0\0\x03\0\0\x02\0\0");
        let mut content = profile;
        if !valid {
            // This tag's declared extent exceeds its profile envelope.
            content[140..144].copy_from_slice(&u32::MAX.to_be_bytes());
        }
        append(&mut webp, b"ICCP", &content);
        append(&mut webp, b"VP8L", b"\x2f\x03\x80\0\0");
        append(
            &mut webp,
            b"EXIF",
            b"Exif\0\0II*\0\x08\0\0\0\x01\0\x0f\x01\x02\0\x04\0\0\0Cam\0\0\0\0\0",
        );
        let length = webp.len() as u32 - 8;
        webp[4..8].copy_from_slice(&length.to_le_bytes());
        fs::write(&path, &webp)?;
        let policy = Policy {
            max_metadata_bytes: if allowed { 4096 } else { 220 },
            ..Default::default()
        };
        inspect_with_metadata(
            &path,
            Limits::default(),
            policy,
            MetadataSettings::default(),
            |_| Control::Continue,
            |object| {
                let metadata = decoded(&object.metadata, policy)?;
                let item = metadata
                    .items()
                    .find(|item| item.kind == formats::icc::KIND);
                assert_eq!(
                    item.map(|item| item.data),
                    (valid && allowed).then_some(profile.as_slice())
                );
                if let Some(item) = item {
                    assert_eq!(item.format, md::Format::Binary);
                    assert_eq!(item.mime, Some(formats::icc::MIME));
                    assert_eq!(item.text(), None);
                }
                assert!(
                    metadata
                        .items()
                        .any(|item| item.kind == 95 && item.text() == Some(b"Cam"))
                );
                assert!(!object.keywords.iter().any(|term| term == b"icc"));
                Ok(())
            },
        )?;
    }
    Ok(())
}

type TiffField = (u16, u16, u64, [u8; 8]);

fn write_ifd(file: &mut File, at: u64, big: bool, fields: &[TiffField]) -> std::io::Result<()> {
    let mut bytes = Vec::new();
    if big {
        bytes.extend_from_slice(&(fields.len() as u64).to_le_bytes());
    } else {
        bytes.extend_from_slice(&(fields.len() as u16).to_le_bytes());
    }
    let width = if big { 8 } else { 4 };
    for (tag, kind, count, value) in fields {
        bytes.extend_from_slice(&tag.to_le_bytes());
        bytes.extend_from_slice(&kind.to_le_bytes());
        bytes.extend_from_slice(&count.to_le_bytes()[..width]);
        bytes.extend_from_slice(&value[..width]);
    }
    bytes.extend_from_slice(&[0; 8][..width]);
    file.seek(std::io::SeekFrom::Start(at))?;
    file.write_all(&bytes)
}

#[test]
fn tiff_metadata_follows_sparse_directories_within_the_probe_budget()
-> Result<(), Box<dyn StdError>> {
    const STRIP: u64 = 4096;
    const IMAGE: u64 = 8192;
    const PHOTO: u64 = 12_288;
    const MAKE: u64 = 16_384;
    const SOFTWARE: u64 = MAKE + 16;
    const DATE: u64 = SOFTWARE + 8;
    const EXPOSURE: u64 = DATE + 24;
    const RESOLUTION: u64 = EXPOSURE + 8;
    const SOFTWARE_TEXT: &[u8; 8] = b"CamTool\0";
    let directory = Directory::new()?;
    let root = gnunet_native::filesystem::Directory::open(&directory.0)?;
    let policy = Policy {
        max_probe_bytes: 448,
        ..Default::default()
    };

    for (name, big) in [("classic.tif", false), ("big.tif", true)] {
        let path = directory.0.join(name);
        let mut input = root.create_private_file(std::ffi::OsStr::new(name))?;
        if big {
            input.write_all(b"II\x2b\0\x08\0\0\0")?;
            input.write_all(&IMAGE.to_le_bytes())?;
        } else {
            input.write_all(b"II\x2a\0")?;
            input.write_all(&(IMAGE as u32).to_le_bytes())?;
        }
        input.seek(std::io::SeekFrom::Start(STRIP))?;
        input.write_all(&[0x80; 320])?;
        input.seek(std::io::SeekFrom::Start(MAKE))?;
        input.write_all(b"Camera Make\0")?;
        input.seek(std::io::SeekFrom::Start(SOFTWARE))?;
        input.write_all(SOFTWARE_TEXT)?;
        input.write_all(b"2026:11:20 06:07:08\0")?;
        // RATIONAL is a pair of little-endian LONGs in both profiles.
        let exposure = ((125_u64 << 32) | 1).to_le_bytes();
        let resolution = ((1_u64 << 32) | 72).to_le_bytes();
        let cell = |value: u64| value.to_le_bytes();
        let (exposure, resolution) = if big {
            (exposure, resolution)
        } else {
            // Classic TIFF's four-byte cells only retain the original offsets.
            // BigTIFF stores this same data directly in its eight-byte cells.
            input.seek(std::io::SeekFrom::Start(EXPOSURE))?;
            input.write_all(&exposure)?;
            input.write_all(&resolution)?;
            (cell(EXPOSURE), cell(RESOLUTION))
        };
        write_ifd(
            &mut input,
            IMAGE,
            big,
            &[
                (256, 4, 1, cell(320)),
                (257, 4, 1, cell(1)),
                (258, 3, 1, cell(8)),
                (259, 3, 1, cell(1)),
                (262, 3, 1, cell(1)),
                (271, 2, 12, cell(MAKE)),
                (273, 4, 1, cell(STRIP)),
                (277, 3, 1, cell(1)),
                (278, 4, 1, cell(1)),
                (279, 4, 1, cell(320)),
                (282, 5, 1, resolution),
                (283, 5, 1, resolution),
                (296, 3, 1, cell(2)),
                (305, 2, 8, if big { *SOFTWARE_TEXT } else { cell(SOFTWARE) }),
                (306, 2, 20, cell(DATE)),
                (0x8769, if big { 18 } else { 4 }, 1, cell(PHOTO)),
            ],
        )?;
        write_ifd(&mut input, PHOTO, big, &[(0x829a, 5, 1, exposure)])?;
        input.seek(std::io::SeekFrom::Start(17))?;
        let keywords = file_keywords(&input, &path, policy, |_| Control::Continue)?;
        let report = inspect_with_metadata(
            &path,
            Limits::default(),
            policy,
            MetadataSettings::default(),
            |_| Control::Continue,
            |object| {
                let metadata = decoded(&object.metadata, policy)?;
                for (kind, expected) in [
                    (1, b"image/tiff".as_slice()),
                    (112, b"320x1".as_slice()),
                    (95, b"Camera Make".as_slice()),
                    (97, b"1/125 s".as_slice()),
                    (56, b"CamTool".as_slice()),
                    (58, b"2026:11:20 06:07:08".as_slice()),
                ] {
                    assert!(
                        metadata
                            .items()
                            .any(|entry| entry.kind == kind && entry.text() == Some(expected)),
                        "{name} metadata kind {kind}"
                    );
                }
                assert_eq!(object.keywords, keywords);
                Ok(())
            },
        )?;
        assert_eq!(report.objects, 1);
        assert_eq!(report.source_bytes, input.metadata()?.len());
        assert_eq!(input.stream_position()?, 17);
    }
    Ok(())
}

// IPTC 1:90 selects UTF-8. The remaining datasets carry the record version,
// two keywords, city, sublocation and country.
const IPTC_PROFILE: &[u8] = b"\x1c\x01\x5a\0\x03\x1b%G\x1c\x02\0\0\x02\0\x04\
    \x1c\x02\x19\0\x0bPra\xc3\xa7a Azul\x1c\x02\x19\0\x0dMarket Street\
    \x1c\x02\x5a\0\x0aS\xc3\xa3o Paulo\x1c\x02\x5c\0\x06Centro\x1c\x02\x65\0\x06Brasil";
const DECOY_IPTC: &[u8] =
    b"\x1c\x01\x5a\0\x03\x1b%G\x1c\x02\0\0\x02\0\x04\x1c\x02\x19\0\x09Untracked";

fn photoshop_resource(
    output: &mut Vec<u8>,
    id: u16,
    name: &[u8],
    data: &[u8],
) -> Result<(), std::num::TryFromIntError> {
    output.extend_from_slice(b"8BIM");
    output.extend_from_slice(&id.to_be_bytes());
    output.push(u8::try_from(name.len())?);
    output.extend_from_slice(name);
    if name.len().is_multiple_of(2) {
        output.push(0);
    }
    output.extend_from_slice(&u32::try_from(data.len())?.to_be_bytes());
    output.extend_from_slice(data);
    if !data.len().is_multiple_of(2) {
        output.push(0);
    }
    Ok(())
}

#[test]
fn jpeg_iptc_crosses_app13_segments_after_skipping_unrelated_image_data()
-> Result<(), Box<dyn StdError>> {
    const PHOTOSHOP: &[u8] = b"Photoshop 3.0\0";
    let directory = Directory::new()?;
    let path = directory.0.join("jpeg-iptc.jpg");
    let root = gnunet_native::filesystem::Directory::open(&directory.0)?;
    let mut input = root.create_private_file(std::ffi::OsStr::new("jpeg-iptc.jpg"))?;
    input.write_all(b"\xff\xd8\xff\xe2\x40\x02")?;
    let skipped_at = input.stream_position()?;
    let mut skipped = PHOTOSHOP.to_vec();
    photoshop_resource(&mut skipped, 0x0404, b"", DECOY_IPTC)?;
    input.write_all(&skipped)?;
    input.seek(std::io::SeekFrom::Start(skipped_at + 16_384))?;

    let mut resources = Vec::new();
    // The first block's even-length name and odd-length data both need pads.
    photoshop_resource(&mut resources, 0x0fab, b"xy", DECOY_IPTC)?;
    photoshop_resource(&mut resources, 0x0404, b"", IPTC_PROFILE)?;
    let (first, second) = resources.split_at(resources.len() - 7);
    for part in [first, second] {
        input.write_all(b"\xff\xed")?;
        input.write_all(&u16::try_from(2 + PHOTOSHOP.len() + part.len())?.to_be_bytes())?;
        input.write_all(PHOTOSHOP)?;
        input.write_all(part)?;
    }

    write_jpeg_grayscale_pixel(&mut input)?;
    assert_iptc_publication(&mut input, &path, b"image/jpeg", 256)
}

#[test]
fn exv_publishes_iptc_and_xmp_from_its_metadata_markers() -> Result<(), Box<dyn StdError>> {
    const XMP: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:x="http://ns.adobe.com/xap/1.0/"><r:Description x:CreatorTool="Sidecar editor"/></r:RDF>"#;
    let directory = Directory::new()?;
    let name = std::ffi::OsStr::new("image.exv");
    let path = directory.0.join(name);
    let root = gnunet_native::filesystem::Directory::open(&directory.0)?;
    let mut input = root.create_private_file(name)?;
    input.write_all(b"\xff\x01Exiv2\xff\xe2\x20\x02")?;
    let skipped_at = input.stream_position()?;
    input.write_all(DECOY_IPTC)?;
    input.seek(std::io::SeekFrom::Start(skipped_at + 8192))?;

    let mut iptc = b"Photoshop 3.0\0".to_vec();
    photoshop_resource(&mut iptc, 0x0404, b"", IPTC_PROFILE)?;
    let mut xmp = b"http://ns.adobe.com/xap/1.0/\0".to_vec();
    xmp.extend_from_slice(XMP);
    for (marker, body) in [(0xed, iptc), (0xe1, xmp)] {
        input.write_all(&[0xff, marker])?;
        input.write_all(&u16::try_from(body.len() + 2)?.to_be_bytes())?;
        input.write_all(&body)?;
    }
    input.write_all(b"\xff\xd9")?;

    let policy = Policy {
        max_probe_bytes: 512,
        ..Default::default()
    };
    let report = inspect_with_metadata(
        &path,
        Limits::default(),
        policy,
        MetadataSettings::default(),
        |_| Control::Continue,
        |object| {
            let metadata = decoded(&object.metadata, policy)?;
            for (kind, value) in [
                (1, b"image/x-exv".as_slice()),
                (49, b"Market Street"),
                (56, b"Sidecar editor"),
            ] {
                assert!(
                    metadata
                        .items()
                        .any(|item| item.kind == kind && item.text() == Some(value))
                );
            }
            assert!(!metadata.items().any(|item| item.kind == 112));
            assert!(object.keywords.iter().any(|term| term == b"market street"));
            assert!(!object.keywords.iter().any(|term| term == b"untracked"));
            Ok(())
        },
    )?;
    assert_eq!(report.objects, 1);
    Ok(())
}

#[test]
fn jpeg_xmp_reassembles_only_the_matching_extension_before_publication()
-> Result<(), Box<dyn StdError>> {
    use md5::{Digest, Md5};
    use std::fmt::Write as _;

    const STANDARD: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
    const EXTENDED: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
    const EXTENSION: &str = r#"<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:xmp="http://ns.adobe.com/xap/1.0/"
 xmlns:lr="http://ns.adobe.com/lightroom/1.0/" xmp:CreatorTool="Native editor">
<lr:hierarchicalSubject><rdf:Bag><rdf:li>Café</rdf:li><rdf:li>Market</rdf:li></rdf:Bag></lr:hierarchicalSubject>
</rdf:Description></rdf:RDF>"#;
    let mut guid = String::with_capacity(32);
    for byte in Md5::digest(EXTENSION.as_bytes()) {
        write!(&mut guid, "{byte:02X}")?;
    }
    let standard = format!(
        r#"<?xpacket begin="{bom}" id="W5M0MpCehiHzreSzNTczkc9d"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
<rdf:Description rdf:about="" xmlns:ps="http://ns.adobe.com/photoshop/1.0/"
 xmlns:note="http://ns.adobe.com/xmp/note/" ps:City="Málaga" note:HasExtendedXMP="{guid}"/>
</rdf:RDF><?xpacket end="w"?>"#,
        bom = '\u{feff}'
    );
    let length = u32::try_from(EXTENSION.len())?.to_be_bytes();
    let split = EXTENSION.find('é').ok_or("missing split character")? + 1;
    let tamper_at = EXTENSION.find("Native editor").ok_or("missing creator")?;
    let directory = Directory::new()?;
    let root = gnunet_native::filesystem::Directory::open(&directory.0)?;
    let policy = Policy {
        max_probe_bytes: 1280,
        ..Default::default()
    };
    let app1 = |input: &mut File, fields: &[&[u8]]| -> Result<(), Box<dyn StdError>> {
        let len = u16::try_from(2 + fields.iter().map(|field| field.len()).sum::<usize>())?;
        input.write_all(b"\xff\xe1")?;
        input.write_all(&len.to_be_bytes())?;
        for field in fields {
            input.write_all(field)?;
        }
        Ok(())
    };

    for (name, tampered) in [("extended.jpg", false), ("tampered.jpg", true)] {
        let path = directory.0.join(name);
        let mut input = root.create_private_file(std::ffi::OsStr::new(name))?;
        input.write_all(b"\xff\xd8\xff\xe2\x40\x02")?;
        let skipped_at = input.stream_position()?;
        let decoy = standard.replace("Málaga", "Decoy city");
        app1(&mut input, &[STANDARD, decoy.as_bytes()])?;
        input.seek(std::io::SeekFrom::Start(skipped_at + 16_384))?;

        app1(
            &mut input,
            &[EXTENDED, b"00000000000000000000000000000000", &[0; 8], b"x"],
        )?;
        let mut packet = EXTENSION.as_bytes().to_vec();
        if tampered {
            packet[tamper_at] = b'F';
        }
        let (first, second) = packet.split_at(split);
        for (offset, chunk) in [(split, second), (0, first)] {
            app1(
                &mut input,
                &[
                    EXTENDED,
                    guid.as_bytes(),
                    &length,
                    &u32::try_from(offset)?.to_be_bytes(),
                    chunk,
                ],
            )?;
        }
        app1(&mut input, &[STANDARD, standard.as_bytes()])?;
        write_jpeg_grayscale_pixel(&mut input)?;

        input.seek(std::io::SeekFrom::Start(17))?;
        let keywords = file_keywords(&input, &path, policy, |_| Control::Continue)?;
        let report = inspect_with_metadata(
            &path,
            Limits::default(),
            policy,
            MetadataSettings::default(),
            |_| Control::Continue,
            |object| {
                let metadata = decoded(&object.metadata, policy)?;
                let contains = |kind, text: &[u8]| {
                    metadata
                        .items()
                        .any(|item| item.kind == kind && item.text() == Some(text))
                };
                assert!(contains(1, b"image/jpeg"));
                assert!(contains(112, b"1x1"));
                assert!(contains(41, "Málaga".as_bytes()));
                assert!(!contains(41, b"Decoy city"));
                assert_eq!(contains(56, b"Native editor"), !tampered);
                assert_eq!(contains(52, "Café, Market".as_bytes()), !tampered);
                assert_eq!(
                    metadata
                        .items()
                        .filter(|item| matches!(item.kind, 52 | 56))
                        .count(),
                    if tampered { 0 } else { 2 }
                );
                assert_eq!(object.keywords, keywords);
                assert_eq!(
                    object.keywords.iter().any(|term| term == b"market"),
                    !tampered
                );
                Ok(())
            },
        )?;
        assert_eq!(report.objects, 1);
        assert_eq!(report.source_bytes, input.metadata()?.len());
        assert_eq!(input.stream_position()?, 17);
    }
    Ok(())
}

fn write_jpeg_grayscale_pixel(output: &mut impl Write) -> std::io::Result<()> {
    // One neutral grayscale pixel with a unit quantization table.
    output.write_all(b"\xff\xdb\0\x43\0")?;
    output.write_all(&[1; 64])?;
    output.write_all(b"\xff\xc0\0\x0b\x08\0\x01\0\x01\x01\x01\x11\0")?;
    for table in [0, 0x10] {
        output.write_all(&[0xff, 0xc4, 0, 20, table, 1])?;
        output.write_all(&[0; 16])?;
    }
    output.write_all(b"\xff\xda\0\x08\x01\x01\0\0\x3f\0\x3f\xff\xd9")
}

#[test]
fn tiff_iptc_supports_packed_long_values_raw_bytes_and_photoshop_resources()
-> Result<(), Box<dyn StdError>> {
    const STRIP: u64 = 4096;
    const DIRECTORY: u64 = 8192;
    const IPTC: u64 = 12_288;
    let directory = Directory::new()?;
    let root = gnunet_native::filesystem::Directory::open(&directory.0)?;
    let mut packed = IPTC_PROFILE.to_vec();
    packed.resize(packed.len().next_multiple_of(4), 0);
    for word in packed.as_chunks_mut::<4>().0 {
        word.reverse();
    }
    let mut resources = Vec::new();
    photoshop_resource(&mut resources, 0x0404, b"", IPTC_PROFILE)?;
    for (name, big, tag, kind, count, payload) in [
        (
            "packed-iptc.tif",
            false,
            33723,
            4,
            packed.len() / 4,
            packed.as_slice(),
        ),
        (
            "byte-iptc.tif",
            true,
            33723,
            1,
            IPTC_PROFILE.len(),
            IPTC_PROFILE,
        ),
        (
            "resource-iptc.tif",
            false,
            34377,
            1,
            resources.len(),
            resources.as_slice(),
        ),
    ] {
        let path = directory.0.join(name);
        let mut input = root.create_private_file(std::ffi::OsStr::new(name))?;
        if big {
            input.write_all(b"II\x2b\0\x08\0\0\0")?;
            input.write_all(&DIRECTORY.to_le_bytes())?;
        } else {
            input.write_all(b"II\x2a\0")?;
            input.write_all(&(DIRECTORY as u32).to_le_bytes())?;
        }
        input.seek(std::io::SeekFrom::Start(STRIP))?;
        input.write_all(&[0x80])?;
        input.seek(std::io::SeekFrom::Start(IPTC))?;
        input.write_all(payload)?;
        let cell = |value: u64| value.to_le_bytes();
        write_ifd(
            &mut input,
            DIRECTORY,
            big,
            &[
                (256, 4, 1, cell(1)),
                (257, 4, 1, cell(1)),
                (258, 3, 1, cell(8)),
                (259, 3, 1, cell(1)),
                (262, 3, 1, cell(1)),
                (273, 4, 1, cell(STRIP)),
                (277, 3, 1, cell(1)),
                (278, 4, 1, cell(1)),
                (279, 4, 1, cell(1)),
                (tag, kind, count as u64, cell(IPTC)),
            ],
        )?;
        assert_iptc_publication(&mut input, &path, b"image/tiff", 384)?;
    }
    Ok(())
}

#[test]
fn positioned_iptc_uses_photoshop_and_jpeg_2000_metadata_containers()
-> Result<(), Box<dyn StdError>> {
    const PADDING: u32 = 16_384;
    const IPTC_UUID: &[u8; 16] =
        b"\x33\xc7\xa4\xd2\xb8\x1d\x47\x23\xa0\xba\xf1\xa3\xe0\x97\xad\x38";
    // A single grayscale pixel encoded by OpenJPEG, with the codestream box at byte 77.
    const JP2: &[u8] =
        b"\x00\x00\x00\x0c\x6a\x50\x20\x20\x0d\x0a\x87\x0a\x00\x00\x00\x14\x66\x74\x79\x70\
        \x6a\x70\x32\x20\x00\x00\x00\x00\x6a\x70\x32\x20\x00\x00\x00\x2d\x6a\x70\x32\x68\
        \x00\x00\x00\x16\x69\x68\x64\x72\x00\x00\x00\x01\x00\x00\x00\x01\x00\x01\x07\x07\
        \x00\x00\x00\x00\x00\x0f\x63\x6f\x6c\x72\x01\x00\x00\x00\x00\x00\x11\x00\x00\x00\
        \x81\x6a\x70\x32\x63\xff\x4f\xff\x51\x00\x29\x00\x00\x00\x00\x00\x01\x00\x00\x00\
        \x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\
        \x00\x00\x00\x00\x00\x00\x01\x07\x01\x01\xff\x52\x00\x0c\x00\x00\x00\x01\x00\x00\
        \x04\x04\x00\x01\xff\x5c\x00\x04\x40\x40\xff\x64\x00\x25\x00\x01\x43\x72\x65\x61\
        \x74\x65\x64\x20\x62\x79\x20\x4f\x70\x65\x6e\x4a\x50\x45\x47\x20\x76\x65\x72\x73\
        \x69\x6f\x6e\x20\x32\x2e\x35\x2e\x34\xff\x90\x00\x0a\x00\x00\x00\x00\x00\x0f\x00\
        \x01\xff\x93\x80\xff\xd9";
    let directory = Directory::new()?;
    let root = gnunet_native::filesystem::Directory::open(&directory.0)?;
    for (name, version) in [("profile.psd", 1_u8), ("profile.psb", 2)] {
        let path = directory.0.join(name);
        let mut input = root.create_private_file(std::ffi::OsStr::new(name))?;
        let mut resources = Vec::new();
        photoshop_resource(&mut resources, 0x0404, b"", IPTC_PROFILE)?;
        input.write_all(b"8BPS\0")?;
        input.write_all(&[version])?;
        input.write_all(b"\0\0\0\0\0\0\0\x01\0\0\0\x01\0\0\0\x01\0\x08\0\x01\0\0\0\0")?;
        input.write_all(&(12 + PADDING + u32::try_from(resources.len())?).to_be_bytes())?;
        input.write_all(b"8BIM\x0f\xab\0\0")?;
        input.write_all(&PADDING.to_be_bytes())?;
        let padding = input.stream_position()?;
        input.write_all(DECOY_IPTC)?;
        input.seek(std::io::SeekFrom::Start(padding + u64::from(PADDING)))?;
        input.write_all(&resources)?;
        let layer_length_bytes = usize::from(version) * 4;
        input.write_all(&[0; 8][..layer_length_bytes])?;
        input.write_all(b"\0\0\x80")?;
        assert_iptc_publication(&mut input, &path, b"image/vnd.adobe.photoshop", 256)?;
    }

    let path = directory.0.join("profile.jp2");
    let mut input = root.create_private_file(std::ffi::OsStr::new("profile.jp2"))?;
    input.write_all(&JP2[..77])?;
    input.write_all(&(8 + PADDING).to_be_bytes())?;
    input.write_all(b"free")?;
    let padding = input.stream_position()?;
    input.write_all(DECOY_IPTC)?;
    input.seek(std::io::SeekFrom::Start(padding + u64::from(PADDING)))?;
    input.write_all(b"\0\0\0\x01uuid")?;
    input.write_all(&(32 + IPTC_PROFILE.len() as u64).to_be_bytes())?;
    input.write_all(IPTC_UUID)?;
    input.write_all(IPTC_PROFILE)?;
    input.write_all(&JP2[77..])?;
    assert_iptc_publication(&mut input, &path, b"image/jp2", 256)
}

fn assert_iptc_publication(
    input: &mut File,
    path: &Path,
    mime: &[u8],
    max_probe_bytes: usize,
) -> Result<(), Box<dyn StdError>> {
    let policy = Policy {
        max_probe_bytes,
        ..Default::default()
    };
    input.seek(std::io::SeekFrom::Start(17))?;
    let keywords = file_keywords(input, path, policy, |_| Control::Continue)?;
    let report = inspect_with_metadata(
        path,
        Limits::default(),
        policy,
        MetadataSettings::default(),
        |_| Control::Continue,
        |object| {
            let metadata = decoded(&object.metadata, policy)?;
            for (kind, text) in [
                (1, mime),
                (112, b"1x1"),
                (49, "Praça Azul".as_bytes()),
                (49, b"Market Street"),
                (41, "São Paulo".as_bytes()),
                (42, b"Centro"),
                (43, b"Brasil"),
            ] {
                assert!(
                    metadata
                        .items()
                        .any(|item| item.kind == kind && item.text() == Some(text)),
                    "{} metadata kind {kind}",
                    path.display()
                );
            }
            assert_eq!(metadata.items().filter(|item| item.kind == 49).count(), 2);
            assert_eq!(object.keywords, keywords);
            assert!(object.keywords.iter().any(|term| term == b"market street"));
            assert!(
                object
                    .keywords
                    .iter()
                    .any(|term| term == "prac\u{0327}a azul".as_bytes())
            );
            assert!(!object.keywords.iter().any(|term| term == b"untracked"));
            Ok(())
        },
    )?;
    assert_eq!(report.objects, 1);
    assert_eq!(report.source_bytes, input.metadata()?.len());
    assert_eq!(input.stream_position()?, 17);
    Ok(())
}

#[test]
fn pdf_metadata_uses_the_info_object_identified_by_the_final_xref() -> Result<(), Box<dyn StdError>>
{
    const STREAM_BYTES: u64 = 16 * 1024;
    const PAYLOAD_COMMENT: &[u8] = b"% /Title (Payload decoy) /Author (Fake Person)\n";
    let directory = Directory::new()?;
    let name = std::ffi::OsStr::new("document.pdf");
    let path = directory.0.join(name);
    let root = gnunet_native::filesystem::Directory::open(&directory.0)?;
    let mut input = root.create_private_file(name)?;
    input.write_all(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")?;
    let mut offsets = [0; 5];
    for (index, body) in [
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources <<>> /Contents 5 0 R >>",
        r"<< /Title (Technical \(Manual\)) /Author (Example Author) /Keywords <536369656E7469666963204E6F746573> /CreationDate (D:20240101012000+01'30') >>",
    ]
    .into_iter()
    .enumerate()
    {
        offsets[index] = input.stream_position()?;
        writeln!(input, "{} 0 obj\n{body}\nendobj", index + 1)?;
    }
    offsets[4] = input.stream_position()?;
    writeln!(input, "5 0 obj\n<< /Length {STREAM_BYTES} >>\nstream")?;
    let stream_start = input.stream_position()?;
    input.seek(std::io::SeekFrom::Start(
        stream_start + STREAM_BYTES - 1 - PAYLOAD_COMMENT.len() as u64,
    ))?;
    input.write_all(b"\n")?;
    input.write_all(PAYLOAD_COMMENT)?;
    input.write_all(b"\nendstream\nendobj\n")?;
    let xref = input.stream_position()?;
    writeln!(input, "xref\n0 6\n0000000000 65535 f ")?;
    for offset in offsets {
        writeln!(input, "{offset:010} 00000 n ")?;
    }
    writeln!(
        input,
        "trailer\n<< /Size 6 /Root 1 0 R /Info 4 0 R >>\nstartxref\n{xref}\n%%EOF"
    )?;

    let policy = Policy {
        max_probe_bytes: 4096,
        ..Default::default()
    };
    input.seek(std::io::SeekFrom::Start(17))?;
    let keywords = file_keywords(&input, &path, policy, |_| Control::Continue)?;
    let report = inspect_with_metadata(
        &path,
        Limits::default(),
        policy,
        MetadataSettings::default(),
        |_| Control::Continue,
        |object| {
            let metadata = decoded(&object.metadata, policy)?;
            for (kind, expected) in [
                (1, b"application/pdf".as_slice()),
                (4, b"Technical (Manual)".as_slice()),
                (11, b"1".as_slice()),
                (13, b"Example Author".as_slice()),
                (49, b"Scientific Notes".as_slice()),
                (54, b"PDF 1.4".as_slice()),
                (58, b"2023-12-31 23:50:00".as_slice()),
            ] {
                assert!(
                    metadata
                        .items()
                        .any(|item| item.kind == kind && item.text() == Some(expected)),
                    "PDF metadata kind {kind}"
                );
            }
            assert_eq!(metadata.items().filter(|item| item.kind == 4).count(), 1);
            assert_eq!(object.keywords, keywords);
            assert!(
                object
                    .keywords
                    .iter()
                    .any(|term| term == b"scientific notes")
            );
            Ok(())
        },
    )?;
    assert_eq!(report.objects, 1);
    assert_eq!(report.source_bytes, input.metadata()?.len());
    assert_eq!(input.stream_position()?, 17);
    Ok(())
}

#[test]
fn pdf_external_streams_require_exact_document_bound_payloads() -> Result<(), Box<dyn StdError>> {
    const XML: &[u8] = br#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><r:Description xmlns:p="http://ns.adobe.com/photoshop/1.0/" p:City="Seoul"/></r:RDF>"#;
    const OBJECTS: &[u8] = b"5 0 << /Title (External document information) >>";

    fn document(spec: &str) -> Result<Vec<u8>, Box<dyn StdError>> {
        let mut pdf = b"%PDF-2.0\n".to_vec();
        let mut rows = [[0; 7]; 9];
        rows[0][5..].fill(255);
        for (id, body) in [
            (1, "<< /Type /Catalog /Pages 2 0 R /Metadata 3 0 R >>"),
            (2, "<< /Type /Pages /Count 1 >>"),
            (4, spec),
            (7, "<FEFF00E9002E0078006D00700020>"), // "é.xmp " has a trailing space.
        ] {
            rows[id] = row(1, pdf.len() as u32);
            writeln!(pdf, "{id} 0 obj\n{body}\nendobj")?;
        }
        rows[3] = row(1, pdf.len() as u32);
        pdf.extend_from_slice(
            b"3 0 obj\n<< /Type /Metadata /Subtype /XML /Length 7 /F 4 0 R \
              /Filter /DCTDecode /FFilter /ASCIIHexDecode >>\nstream\nignored\nendstream\nendobj\n",
        );
        rows[6] = row(1, pdf.len() as u32);
        pdf.extend_from_slice(
            b"6 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length 0 /F (objects.bin) >>\nstream\n\nendstream\nendobj\n",
        );
        rows[5] = row(2, 6);
        let xref = pdf.len();
        // The xref goes last, with object 8 used for its own direct entry.
        rows[8] = row(1, xref as u32);
        writeln!(
            pdf,
            "8 0 obj\n<< /Type /XRef /Root 1 0 R /Info 5 0 R /Size 9 /W [1 4 2] /Length 63 >>\nstream"
        )?;
        pdf.extend_from_slice(rows.as_flattened());
        writeln!(pdf, "\nendstream\nendobj\nstartxref\n{xref}\n%%EOF")?;
        Ok(pdf)
    }

    fn row(kind: u8, offset: u32) -> [u8; 7] {
        let mut bytes = [0; 7];
        bytes[0] = kind;
        bytes[1..5].copy_from_slice(&offset.to_be_bytes());
        bytes
    }

    let directory = Directory::new()?;
    let source = directory.0.join("original.pdf");
    let copy = directory.0.join("copy.pdf");
    let mut packet = Vec::new();
    for byte in XML {
        write!(packet, "{byte:02X}")?;
    }
    packet.push(b'>');
    fs::write(directory.0.join("external.xmp"), &packet)?;

    for (spec, name) in [
        ("(external.xmp)", PdfExternalName::File(b"external.xmp")),
        (
            "<< /UF 7 0 R /F (fallback.xmp) >>",
            PdfExternalName::UnicodeFile("é.xmp "),
        ),
        (
            "<< /FS /URL /F (https://example.invalid/metadata) >>",
            PdfExternalName::Url(b"https://example.invalid/metadata"),
        ),
    ] {
        let bytes = document(spec)?;
        fs::write(&source, &bytes)?;
        fs::write(&copy, &bytes)?;
        let original = File::open(&source)?;
        let mut streams = PdfExternalStreams::default();
        streams.bind(&original, name, &packet)?;
        streams.bind(&original, PdfExternalName::File(b"objects.bin"), OBJECTS)?;
        assert!(streams.bind(&original, name, b"replacement").is_err());
        let settings = MetadataSettings::default().with_pdf_external_streams(streams);
        let snapshot = settings.snapshot()?;
        let restored = MetadataSettings::from_snapshot(&snapshot)?;
        assert_eq!(restored.snapshot()?, snapshot);

        #[cfg(feature = "network")]
        {
            use crate::unindex_task::{Limits as TaskLimits, Task};

            let task_dir = directory.0.join(format!("unindex-{}", spec.len()));
            let limits = TaskLimits::default();
            let task = Task::create(&task_dir, &source, &[], settings.clone(), limits)?;
            let id = *task.task_id();
            drop(task);
            let reopened = Task::open(&task_dir, limits)?;
            assert_eq!(*reopened.task_id(), id);
            assert_eq!(reopened.manifest().metadata.snapshot()?, snapshot);
            let current = fs::File::open(&source)?;
            let live = file_keywords_with_metadata(
                &current,
                &source,
                Policy::default(),
                settings.clone(),
                |_| Control::Continue,
            )?;
            let recovered = file_keywords_for_verified_source(
                &current,
                &source,
                reopened.manifest().metadata.clone(),
                VerifiedSource {
                    observed: descriptor_info(&current)?,
                    digest: gnunet_crypto::hash512(&bytes),
                },
                |_| Control::Continue,
            )?;
            assert_eq!(recovered, live);
        }

        for (path, settings, limit, title, city) in [
            (&source, settings.clone(), 4096, true, true),
            (&source, restored.clone(), 4096, true, true),
            (&copy, restored, 4096, false, false),
            (
                &source,
                settings.clone(),
                bytes.len() + OBJECTS.len() + packet.len() - 1,
                true,
                false,
            ),
            (&source, MetadataSettings::default(), 4096, false, false),
        ] {
            let policy = Policy {
                max_probe_bytes: limit,
                ..Default::default()
            };
            inspect_with_metadata(
                path,
                Limits::default(),
                policy,
                settings,
                |_| Control::Continue,
                |object| {
                    let metadata = decoded(&object.metadata, policy)?;
                    let has = |kind, text| {
                        metadata
                            .items()
                            .any(|item| item.kind == kind && item.text() == Some(text))
                    };
                    assert_eq!(has(4, b"External document information".as_slice()), title);
                    assert_eq!(has(41, b"Seoul".as_slice()), city);
                    assert!(has(11, b"1".as_slice()));
                    Ok(())
                },
            )?;
        }

        let expected = gnunet_crypto::hash512(&bytes);
        let digest_at = snapshot
            .windows(expected.len())
            .position(|window| window == expected)
            .ok_or("missing PDF digest in snapshot")?;
        let mut invalid = snapshot;
        invalid[digest_at] ^= 1;
        let failure = inspect_with_metadata(
            &source,
            Limits::default(),
            Policy::default(),
            MetadataSettings::from_snapshot(&invalid)?,
            |_| Control::Continue,
            |_| Err(Error::Binding),
        );
        assert!(failure.is_err_and(|failure| matches!(failure.cause, Error::SourceChanged)));

        // Holding the same descriptor does not admit a changed file version.
        OpenOptions::new()
            .append(true)
            .open(&source)?
            .write_all(b"\n")?;
        assert!(matches!(settings.snapshot(), Err(Error::SourceChanged)));
    }
    Ok(())
}

#[test]
fn image_dimensions_use_only_the_available_metadata_slots() -> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let path = directory.0.join("image.gif");
    fs::write(&path, b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00\xff\xff\xff\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b")?;
    for max_metadata_items in [2, 3] {
        let policy = Policy {
            max_metadata_items,
            ..Default::default()
        };
        let report = inspect_with_metadata(
            &path,
            Limits::default(),
            policy,
            MetadataSettings::default(),
            |_| Control::Continue,
            |object| {
                let metadata = decoded(&object.metadata, policy)?;
                assert!(
                    metadata
                        .items()
                        .any(|item| item.kind == 1 && item.text() == Some(b"image/gif"))
                );
                assert_eq!(
                    metadata
                        .items()
                        .any(|item| item.kind == 112 && item.text() == Some(b"1x1")),
                    max_metadata_items == 3
                );
                Ok(())
            },
        )?;
        assert_eq!(report.objects, 1);
    }
    Ok(())
}

#[test]
fn descriptor_tree_streams_original_names_and_only_root_manual_metadata()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    fs::create_dir(directory.0.join("nested"))?;
    fs::write(directory.0.join("a.txt"), b"plain")?;
    fs::write(
        directory.0.join("nested").join("b.html"),
        b"<title>Nested actual title</title>",
    )?;
    let mut manual = ManualMetadata::default();
    manual.push(b"title:Manual Root Annotation")?;
    let settings = MetadataSettings::default().with_manual(manual);
    let policy = Policy::default();
    let mut paths = Vec::new();
    let report = inspect_with_metadata(
        &directory.0,
        Limits::default(),
        policy,
        settings,
        |_| Control::Continue,
        |object| {
            let root_annotation = decoded(&object.metadata, policy)?
                .items()
                .any(|item| item.kind == 4 && item.text() == Some(b"Manual Root Annotation"));
            if root_annotation != object.relative.as_os_str().is_empty() {
                return Err(Error::Policy);
            }
            if object
                .keywords
                .iter()
                .any(|term| term == b"Manual Root Annotation")
            {
                return Err(Error::Policy);
            }
            paths.push(object.relative);
            Ok(())
        },
    )?;
    assert_eq!(
        paths,
        [
            PathBuf::new(),
            PathBuf::from("a.txt"),
            PathBuf::from("nested"),
            PathBuf::from("nested/b.html")
        ]
    );
    assert_eq!(
        (report.objects, report.files, report.directories),
        (4, 2, 2)
    );
    assert_eq!(fs::read_dir(&directory.0)?.count(), 2);
    Ok(())
}

#[test]
fn mutation_during_sink_delivery_is_partial_failure_and_not_complete_preview()
-> Result<(), Box<dyn StdError>> {
    let directory = Directory::new()?;
    let path = directory.0.join("actual.txt");
    fs::write(&path, b"original")?;
    let outcome = inspect_with_metadata(
        &path,
        Limits::default(),
        Policy::default(),
        MetadataSettings::default(),
        |_| Control::Continue,
        |_| {
            OpenOptions::new().write(true).open(&path)?.set_len(9)?;
            Ok(())
        },
    );
    let failure = match outcome {
        Ok(_) => return Err("changed source was reported complete".into()),
        Err(failure) => failure,
    };
    assert_eq!(failure.report.objects, 1);
    assert!(matches!(failure.cause, Error::SourceChanged));
    Ok(())
}
