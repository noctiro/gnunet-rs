//! Offline test observer for public FS buffers; no file transfer or service I/O.
use gnunet_fs::content::{self, BlockKey, TAG_BYTES};
use std::{
    error::Error,
    fmt::Write as _,
    io::{self, BufRead, Write as _},
};

fn decode(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if text == "-" {
        return Ok(Vec::new());
    }
    if !text.len().is_multiple_of(2) || text.len() > 2 * (content::BLOCK_BYTES + TAG_BYTES) {
        return Err("hex length".into());
    }
    let nibble = |byte| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    };
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| -> Result<u8, Box<dyn Error>> {
            let high = nibble(pair[0]).ok_or("hex digit")?;
            let low = nibble(pair[1]).ok_or("hex digit")?;
            Ok(high * 16 + low)
        })
        .collect()
}
fn hex(bytes: &[u8]) -> Result<String, Box<dyn Error>> {
    if bytes.is_empty() {
        return Ok("-".into());
    }
    let mut text = String::new();
    for byte in bytes {
        write!(text, "{byte:02x}")?;
    }
    Ok(text)
}
fn main() -> Result<(), Box<dyn Error>> {
    for line in io::stdin().lock().lines() {
        let line = line?;
        let mut fields = line.split_ascii_whitespace();
        let mode = fields.next().ok_or("mode")?;
        let output = match mode {
            "F" => {
                let bytes = decode(fields.next().ok_or("plaintext")?)?;
                let mut output = vec![0; bytes.len() + TAG_BYTES];
                match content::encode_data(&bytes, &mut output) {
                    Ok(block) => format!(
                        "OK {} {} {}",
                        hex(&block.key().key)?,
                        hex(&block.key().query)?,
                        hex(block.bytes())?
                    ),
                    Err(_) => "ERR".into(),
                }
            }
            "O" => {
                let key = decode(fields.next().ok_or("key")?)?
                    .try_into()
                    .map_err(|_| "key64")?;
                let query = decode(fields.next().ok_or("query")?)?
                    .try_into()
                    .map_err(|_| "query64")?;
                let ciphertext = decode(fields.next().ok_or("ciphertext")?)?;
                let mut output = vec![0; ciphertext.len().saturating_sub(TAG_BYTES)];
                match content::open_data(BlockKey { key, query }, &ciphertext, &mut output) {
                    Ok(bytes) => format!("OK {}", hex(bytes)?),
                    Err(_) => "ERR".into(),
                }
            }
            "I" => {
                let bytes = decode(fields.next().ok_or("child entries")?)?;
                if !bytes.len().is_multiple_of(content::CHK_BYTES) {
                    return Err("child entry length".into());
                }
                let children: Vec<_> = bytes
                    .as_chunks::<{ content::CHK_BYTES }>()
                    .0
                    .iter()
                    .map(|entry| {
                        let mut key = [0; 64];
                        let mut query = [0; 64];
                        key.copy_from_slice(&entry[..64]);
                        query.copy_from_slice(&entry[64..]);
                        BlockKey { key, query }
                    })
                    .collect();
                let mut scratch = vec![0; bytes.len()];
                let mut output = vec![0; bytes.len() + TAG_BYTES];
                match content::encode_index(&children, &mut scratch, &mut output) {
                    Ok(block) => format!(
                        "OK {} {} {}",
                        hex(&block.key().key)?,
                        hex(&block.key().query)?,
                        hex(block.bytes())?
                    ),
                    Err(_) => "ERR".into(),
                }
            }
            _ => return Err("mode".into()),
        };
        if fields.next().is_some() {
            return Err("extra fields".into());
        }
        writeln!(io::stdout().lock(), "{output}")?;
    }
    Ok(())
}
