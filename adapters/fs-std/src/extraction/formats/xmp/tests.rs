use std::convert::Infallible;

use super::{Profile, parse_guid, visit};

const RDF_WRAPPER: &str = r#"<r:RDF xmlns:r="http://www.w3.org/1999/02/22-rdf-syntax-ns#">"#;
const XMP_NAMESPACE: &str = r#"xmlns:m="http://ns.adobe.com/xap/1.0/""#;

fn rdf(properties: &str) -> String {
    format!("{RDF_WRAPPER}<r:Description {XMP_NAMESPACE}>{properties}</r:Description></r:RDF>")
}

fn projection(bytes: &[u8], limit: usize) -> Option<Vec<(u32, String)>> {
    let mut output = Vec::new();
    let valid = visit(bytes, limit, &mut |kind, value| {
        output.push((kind, String::from_utf8_lossy(value).into_owned()));
        Ok::<_, Infallible>(())
    })
    .ok()?;
    valid.then_some(output)
}

#[test]
fn projects_gnu_types_by_namespace_for_scalar_and_qualified_properties() {
    let packet = format!(
        "<?xpacket begin=\"\"?>\
         <x:xmpmeta xmlns:x=\"adobe:ns:meta/\">{RDF_WRAPPER}\
         <r:Description {XMP_NAMESPACE} m:Rating=\"4\" \
          xmlns:camera=\"http://ns.adobe.com/photoshop/1.0/\" \
          xmlns:location=\"http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/\" \
          xmlns:tags=\"http://ns.adobe.com/lightroom/1.0/\" \
          xmlns:mp=\"http://ns.microsoft.com/photo/1.0/\" \
          xmlns:xmp=\"urn:unrelated:camera\" xmp:CreatorTool=\"ignored\" \
          location:CountryCode=\"BR\" mp:Rating=\"80\">\
           <camera:Country><![CDATA[Bra]]>sil</camera:Country>\
           <camera:City><r:Alt>\
             <r:li xml:lang=\"en\">São Paulo (English)</r:li>\
             <r:li xml:lang=\"x-default\">São Paulo</r:li>\
           </r:Alt></camera:City>\
           <m:CreatorTool r:parseType=\"Resource\"><r:value r:resource=\"urn:tool:editor?a=1&amp;b=2\"/>\
             <xmp:CreatorTool>also ignored</xmp:CreatorTool></m:CreatorTool>\
           <tags:hierarchicalSubject><r:Bag><r:li>Places|Brazil</r:li>\
             <r:li>Roads|&#x2665;</r:li></r:Bag></tags:hierarchicalSubject>\
         </r:Description></r:RDF></x:xmpmeta><?xpacket end=\"w\"?>"
    );
    assert_eq!(
        projection(packet.as_bytes(), 128),
        Some(
            [
                (43, "Brasil"),
                (41, "São Paulo"),
                (175, "4"),
                (175, "80"),
                (44, "BR"),
                (56, "urn:tool:editor?a=1&b=2"),
                (52, "Places|Brazil, Roads|♥"),
            ]
            .map(|(kind, value)| (kind, value.to_owned()))
            .to_vec()
        )
    );
}

#[test]
fn malformed_and_over_budget_values_do_not_publish_partial_metadata() {
    let packet = rdf("<m:CreatorTool>valid editor</m:CreatorTool>");
    assert_eq!(projection(packet.as_bytes(), 10), Some(Vec::new()));
    assert_eq!(
        projection(format!("<!DOCTYPE a>{packet}").as_bytes(), 128),
        None
    );
    assert_eq!(projection(format!("{packet}extra").as_bytes(), 128), None);
    assert_eq!(
        projection(
            rdf("<m:CreatorTool>&external;</m:CreatorTool>").as_bytes(),
            128
        ),
        None
    );
}

#[test]
fn unicode_packets_and_guid_merge_keep_the_primary_value() {
    const GUID: &[u8] = b"0123456789aBcDEF0123456789AbcDEF";
    let standard = format!(
        "{}<r:Description {XMP_NAMESPACE} m:CreatorTool=\"編集\" \
         xmlns:n=\"http://ns.adobe.com/xmp/note/\" n:HasExtendedXMP=\"{}\"/></r:RDF>",
        RDF_WRAPPER,
        String::from_utf8_lossy(GUID)
    );
    let utf16 = [0xff, 0xfe]
        .into_iter()
        .chain(standard.encode_utf16().flat_map(u16::to_le_bytes))
        .collect::<Vec<_>>();
    let extended = rdf("<m:CreatorTool>other</m:CreatorTool><m:Rating>3</m:Rating>");
    let utf32 = [0, 0, 0xfe, 0xff]
        .into_iter()
        .chain(extended.chars().flat_map(|c| u32::from(c).to_be_bytes()))
        .collect::<Vec<_>>();
    let merged = (|| {
        let mut profile = Profile::parse(&utf16, 128)?;
        let id = profile.extended_id();
        profile.merge(Profile::parse(&utf32, 128)?);
        let mut output = Vec::new();
        profile
            .emit(&mut |kind, value| {
                output.push((kind, String::from_utf8_lossy(value).into_owned()));
                Ok::<_, Infallible>(())
            })
            .ok()?;
        Some((id, output))
    })();
    assert_eq!(
        merged,
        Some((
            parse_guid(GUID),
            vec![(175, "3".to_owned()), (56, "編集".to_owned())]
        ))
    );
}
