//! Pure controlled exporter for the official-C block consumer. No network/key IO.
#[cfg(feature = "alloc")]
mod enabled {
    use gnunet_regex::{Automaton, Limits, Record};
    use std::{
        error::Error,
        fs::{File, create_dir},
        io::{self, Write},
        path::Path,
    };
    fn hex(bytes: &[u8]) -> String {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(char::from(DIGITS[usize::from(byte >> 4)]));
            out.push(char::from(DIGITS[usize::from(byte & 15)]));
        }
        out
    }
    fn fresh(path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut file = File::options().write(true).create_new(true).open(path)?;
        file.write_all(bytes)
    }
    fn emit(
        record: Record<'_>,
        dir: &Path,
        case: usize,
        kind: &str,
        index: usize,
        metadata: &mut Vec<String>,
    ) -> Result<(), Box<dyn Error>> {
        let ordinal = metadata.len();
        let name = format!("artifact-{ordinal:02}");
        let mut block = vec![
            0;
            record
                .encoded_len()
                .map_err(|e| io::Error::other(format!("block length: {e:?}")))?
        ];
        record
            .encode(&mut block)
            .map_err(|e| io::Error::other(format!("block encode: {e:?}")))?;
        let mut expected = format!(
            "KEY {}\nACCEPT {}\nPROOF {}\nEDGES {}\n",
            hex(&record.key),
            u8::from(record.accepting),
            if record.proof.is_empty() {
                "-".into()
            } else {
                hex(record.proof)
            },
            record.edges.len()
        );
        for edge in record.edges {
            expected.push_str(&format!(
                "EDGE {} {}\n",
                hex(&edge.destination()),
                hex(edge.label())
            ));
        }
        fresh(&dir.join(format!("{name}.bin")), &block)?;
        fresh(&dir.join(format!("{name}.expected")), expected.as_bytes())?;
        metadata.push(format!("{{\"file\":\"{name}.bin\",\"expected\":\"{name}.expected\",\"sha256\":\"{}\",\"expected_sha256\":\"{}\",\"case\":{case},\"kind\":\"{kind}\",\"index\":{index},\"key\":\"{}\",\"proof_len\":{},\"accepting\":{},\"edges\":{},\"branch\":{},\"literal_dot\":{},\"nullable\":{},\"prefix24\":{},\"compressed\":{}}}",
            hex(&gnunet_crypto::hash256(&block)), hex(&gnunet_crypto::hash256(expected.as_bytes())), hex(&record.key), record.proof.len(), record.accepting, record.edges.len(),
            record.edges.len() > 1, record.edges.iter().any(|e| e.label().contains(&b'.')),
            record.accepting && record.proof.is_empty(), kind == "initial" && record.proof.len() == 24,
            record.edges.iter().any(|e| e.label().len() > 1)));
        Ok(())
    }
    /// Export two fixed actual compiler results into a fresh caller directory.
    pub(super) fn run() -> Result<(), Box<dyn Error>> {
        let mut args = std::env::args_os();
        let _program = args.next();
        let dir = args
            .next()
            .ok_or("expected a fresh output directory argument")?;
        if args.next().is_some() {
            return Err("unexpected additional argument".into());
        }
        let dir = Path::new(&dir);
        create_dir(dir)?;
        let cases: &[(&[u8], u16)] = &[
            (
                b"GNUNET-VPN-VER-0001-(a|bc)0123456789012345678901234567890123456789",
                0,
            ),
            (b"(.|ab)?c?", 1),
        ];
        let mut metadata = Vec::new();
        for (case, &(expression, compression)) in cases.iter().enumerate() {
            let a = Automaton::compile(expression, compression, Limits::default())
                .map_err(|e| io::Error::other(format!("pure compiler case{case}: {e:?}")))?;
            let first = a.states().first().ok_or("missing actual start state")?;
            emit(first.record(), dir, case, "state", 0, &mut metadata)?;
            if let Some((index, state)) = a
                .states()
                .iter()
                .enumerate()
                .skip(1)
                .find(|(_, s)| s.record().accepting)
            {
                emit(state.record(), dir, case, "state", index, &mut metadata)?;
            }
            let mut selected = 0;
            for i in 0..a.initial_count() {
                let r = a.initial(i).ok_or("initial row missing")?;
                if r.proof.len() == 24 && selected < 2 {
                    emit(r, dir, case, "initial", i, &mut metadata)?;
                    selected += 1;
                }
            }
        }
        let manifest = format!(
            "{{\"schema\":1,\"scope\":\"actual-pure-rust-regex-state-artifacts\",\"cases\":2,\"blocks\":[{}]}}\n",
            metadata.join(",")
        );
        fresh(&dir.join("manifest.json"), manifest.as_bytes())?;
        std::io::stdout().write_all(
            format!(
                "{{\"exported\":{},\"cases\":2,\"native_effects\":false}}\n",
                metadata.len()
            )
            .as_bytes(),
        )?;
        Ok(())
    }
}
#[cfg(feature = "alloc")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    enabled::run()
}
#[cfg(not(feature = "alloc"))]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    Err("state_artifacts requires explicit --features alloc".into())
}
