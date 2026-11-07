//! Test-only line observer over the actual CORE engine. Official-C fixtures own
//! the peer processes/IPC relay; this executable never implements a C backend.
use gnunet_core::{
    session::{Event, Identity, Session},
    wire::WordOrder,
};
use gnunet_crypto::{EddsaPublicKey, Entropy};
use gnunet_types::Error;
use std::{
    env,
    error::Error as StdError,
    fs::File,
    io::{self, BufRead, Read, Write},
};

struct Random(File);
impl Entropy for Random {
    fn fill(&mut self, output: &mut [u8]) -> Result<(), Error> {
        self.0.read_exact(output).map_err(|_| Error::Entropy)
    }
}
fn decode(text: &str) -> Result<Vec<u8>, Box<dyn StdError>> {
    if !text.len().is_multiple_of(2) || text.len() > 2 * 65535 {
        return Err("invalid hex input length".into());
    }
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|bytes| {
            let pair = std::str::from_utf8(bytes)?;
            Ok(u8::from_str_radix(pair, 16)?)
        })
        .collect()
}
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(*byte >> 4)]));
        output.push(char::from(HEX[usize::from(*byte & 15)]));
    }
    output
}
fn main() -> Result<(), Box<dyn StdError>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: cake-observer TEST_SEED_HEX PEER_PUBLIC_HEX".into());
    }
    let seed: [u8; 32] = decode(&args[1])?.try_into().map_err(|_| "seed length")?;
    let peer: [u8; 32] = decode(&args[2])?.try_into().map_err(|_| "peer length")?;
    let identity = Identity::from_seed(seed);
    let mut random = Random(File::open("/dev/urandom")?);
    let mut session = Session::<65535>::new(
        &identity,
        EddsaPublicKey::from_bytes(peer),
        WordOrder::Little,
        b"",
    )?;
    let mut output = vec![0; 65535];
    let mut scratch = vec![0; 65535];
    let mut stdout = io::stdout().lock();
    writeln!(
        stdout,
        "READY\t{}\t{:?}",
        hex(identity.public_key().as_bytes()),
        session.phase()
    )?;
    stdout.flush()?;
    for line in io::stdin().lock().lines() {
        let line = line?;
        let mut fields = line.split_whitespace();
        let command = fields.next().ok_or("missing command")?;
        if command == "quit" {
            break;
        }
        let now: u64 = fields.next().ok_or("missing time")?.parse()?;
        let result = match command {
            "tick" => session.tick(now, &mut random, &mut output),
            "recv" => session.receive(
                now,
                &decode(fields.next().ok_or("missing frame")?)?,
                &mut random,
                &mut output,
                &mut scratch,
            ),
            "send" => session
                .send(
                    now,
                    &decode(fields.next().ok_or("missing payload")?)?,
                    &mut output,
                )
                .map(Event::Send),
            _ => return Err("unknown command".into()),
        };
        match result {
            Ok(event) => {
                let (name, size, payload) = match event {
                    Event::None => ("NONE", 0, false),
                    Event::Send(n) => ("SEND", n, false),
                    Event::Established(n) => ("ESTABLISHED", n, false),
                    Event::Payload(n) => ("PAYLOAD", n, true),
                    Event::Lost => ("LOST", 0, false),
                };
                writeln!(
                    stdout,
                    "OK\t{:?}\t{name}\t{}",
                    session.phase(),
                    hex(if payload {
                        &scratch[..size]
                    } else {
                        &output[..size]
                    })
                )?;
            }
            Err(error) => writeln!(stdout, "ERR\t{:?}\t{error:?}", session.phase())?,
        }
        stdout.flush()?;
    }
    Ok(())
}
