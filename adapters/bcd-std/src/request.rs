use crate::provider::RenderRequest;
use gnunet_gnsrecord::ZoneKey;

/// Original thirteen HTTP form names in the fixed renderer field order.
pub const FIELD_NAMES: [&str; 13] = [
    "prefix",
    "name",
    "suffix",
    "street",
    "city",
    "phone",
    "fax",
    "email",
    "homepage",
    "org",
    "department",
    "subdepartment",
    "jobtitle",
];

/// Independent fixed HTML, containing no request interpolation or remote asset.
pub fn form(full: bool) -> String {
    let target = if full { "full" } else { "simple" };
    let mut html = format!(
        "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>GNS business card</title><h1>GNS business card</h1><p><a href=\"/\">Simple</a> · <a href=\"/full\">Full</a></p><form method=\"get\" action=\"/submit/{target}\"><label>GNS zone public key <input name=\"gnskey\" required maxlength=\"58\"></label><br><label>GNS nickname <input name=\"gnsnick\" maxlength=\"512\"></label><br>"
    );
    for field in FIELD_NAMES {
        html.push_str(&format!(
            "<label>{field} <input name=\"{field}\" maxlength=\"1024\"></label><br>"
        ));
    }
    html.push_str("<label>OpenPGP fingerprint <input name=\"gpgfingerprint\" maxlength=\"1024\"></label><br><label>QR PNG instead of PDF <input type=\"checkbox\" name=\"gnspng\" value=\"1\"></label><br><button>Generate</button></form></html>");
    html
}

fn decode(input: &[u8], maximum: usize) -> Result<String, &'static str> {
    let mut out = Vec::new();
    out.try_reserve_exact(input.len().min(maximum))
        .map_err(|_| "form allocation")?;
    let mut at = 0;
    while at < input.len() {
        let value = match input[at] {
            b'+' => b' ',
            b'%' => {
                let pair = input.get(at + 1..at + 3).ok_or("incomplete URL escape")?;
                let hex = |b: u8| match b {
                    b'0'..=b'9' => Some(b - b'0'),
                    b'a'..=b'f' => Some(b - b'a' + 10),
                    b'A'..=b'F' => Some(b - b'A' + 10),
                    _ => None,
                };
                let value = (hex(pair[0]).ok_or("invalid URL escape")? << 4)
                    | hex(pair[1]).ok_or("invalid URL escape")?;
                at += 2;
                value
            }
            byte => byte,
        };
        if value < 32 || value == 127 {
            return Err("control byte in form field");
        }
        if out.len() == maximum {
            return Err("form field too long");
        }
        out.push(value);
        at += 1;
    }
    String::from_utf8(out).map_err(|_| "invalid form UTF-8")
}

/// Exact form-value bytes are decoded once; duplicate named fields are refused.
/// The supplied public key is validated by the shared typed zone-key parser.
pub(crate) fn parse(
    query: &str,
    full: bool,
    maximum: usize,
    field_bytes: usize,
) -> Result<RenderRequest, &'static str> {
    if query.len() > maximum {
        return Err("form query too long");
    }
    let mut values: [Option<String>; 17] = std::array::from_fn(|_| None);
    for part in query.split('&').filter(|s| !s.is_empty()) {
        let (key, value) = part.split_once('=').unwrap_or((part, ""));
        let key = decode(key.as_bytes(), 64)?;
        if let Some(at) = FIELD_NAMES
            .into_iter()
            .chain(["gpgfingerprint", "gnsnick", "gnskey", "gnspng"])
            .position(|name| name == key)
        {
            if values[at].is_some() {
                return Err("duplicate form field");
            }
            values[at] = Some(decode(value.as_bytes(), field_bytes)?);
        }
    }
    let key = values[15].take().ok_or("GNS public key is required")?;
    ZoneKey::from_ztld(&key).map_err(|_| "invalid typed GNS public key")?;
    let nickname = values[14].take().unwrap_or_default();
    // GNS import does not perform a second generic URI decoding step. Preserve
    // the decoded nickname exactly, including literal '%' and UTF-8. Provider
    // reads this single line with fixed e-TeX readline, never as TeX source.
    let uri = format!("gnunet://gns/{key}/{nickname}");
    Ok(RenderRequest {
        full,
        png: values[16].is_some(),
        uri,
        fields: std::array::from_fn(|i| values[i].take().unwrap_or_default()),
        fingerprint: values[13].take().unwrap_or_default(),
    })
}

#[cfg(test)]
#[expect(
    clippy::panic_in_result_fn,
    reason = "Regression assertions check exact form fields and URI payload preservation"
)]
mod contracts {
    use super::*;
    use gnunet_gnsrecord::{ZONE_TEXT_LEN, ZoneKeyType};

    /// Pure codec/contract source only. This synthetic typed public value makes
    /// no point-validation, cryptographic or successful rendering claim.
    #[test]
    fn once_decoded_nickname_remains_exact_qr_payload() -> Result<(), Box<dyn std::error::Error>> {
        let key = ZoneKey::new(ZoneKeyType::Edkey, [7; 32]);
        let mut text = [0; ZONE_TEXT_LEN];
        let key = key.write_ztld(&mut text)?;
        let query = format!("gnskey={key}&gnsnick=%252F+caf%C3%A9%5C%7B%7D&gnspng=false");
        let request = parse(&query, true, 4096, 1024).map_err(std::io::Error::other)?;
        assert_eq!(request.uri, format!("gnunet://gns/{key}/%2F café\\{{}}"));
        assert!(request.png && request.full);
        assert!(request.fields.iter().all(String::is_empty));
        assert!(parse(&format!("gnskey={key}&gnsnick=%0A"), false, 4096, 1024).is_err());
        Ok(())
    }

    #[test]
    fn all_original_fields_and_absent_optional_values() -> Result<(), Box<dyn std::error::Error>> {
        let key = ZoneKey::new(ZoneKeyType::Pkey, [9; 32]);
        let mut text = [0; ZONE_TEXT_LEN];
        let key = key.write_ztld(&mut text)?;
        let mut query = format!("gnskey={key}&gpgfingerprint=ABCD");
        for (i, field) in FIELD_NAMES.iter().enumerate() {
            query.push_str(&format!("&{field}=value{i}"));
        }
        let request = parse(&query, false, 4096, 1024).map_err(std::io::Error::other)?;
        assert_eq!(request.uri, format!("gnunet://gns/{key}/"));
        assert!(!request.png && !request.full);
        assert_eq!(request.fingerprint, "ABCD");
        for (i, value) in request.fields.iter().enumerate() {
            assert_eq!(*value, format!("value{i}"));
        }
        assert!(parse(&format!("{query}&gnskey={key}"), false, 4096, 1024).is_err());
        assert!(parse("gnskey=not-a-typed-key", false, 4096, 1024).is_err());
        Ok(())
    }
}
