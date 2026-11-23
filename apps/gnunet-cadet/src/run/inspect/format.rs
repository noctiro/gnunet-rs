//! Official management display rows from complete original IPC records.
use crate::Cause;
use gnunet_wire::official::cadet::Response;
use std::io::Write;

pub(super) fn row(out: &mut Vec<u8>, response: Response<'_>) -> Result<(), Cause> {
    out.clear();
    let cap = match response {
        Response::PathInfo { peers, .. } => 64 + 7 * peers.len(),
        _ => 128,
    };
    out.try_reserve_exact(cap)?;
    match response {
        Response::PeerInfo {
            paths,
            tunnel,
            peer,
            ..
        } => {
            write_peer(out, &peer, 52)?;
            writeln!(
                out,
                " tunnel: {}, paths: {paths}",
                if tunnel == 0 { 'N' } else { 'Y' }
            )?;
        }
        Response::TunnelInfo {
            peer,
            channels,
            connections,
            encryption_state,
            connection_state,
        } => {
            write_peer(out, &peer, 52)?;
            let encryption = ["NULL ", "KSENT", "KRECV", "READY"]
                .get(usize::from(encryption_state))
                .copied()
                .unwrap_or("");
            let connection = ["NEW  ", "SRCH ", "WAIT ", "READY", "SHUTD"]
                .get(usize::from(connection_state))
                .copied()
                .unwrap_or("");
            writeln!(
                out,
                " [ENC: {encryption}, CON: {connection}] CHs: {channels}, CONNs: {connections}"
            )?;
        }
        Response::PathInfo { offset, peers } => {
            write!(out, "Path of length {}: ", peers.len())?;
            for (index, peer) in peers.iter().enumerate() {
                let selected = u32::try_from(index) == Ok(offset);
                if selected {
                    out.push(b'*');
                }
                write_peer(out, &peer, 4)?;
                if selected {
                    out.push(b'*');
                }
                out.push(b' ');
            }
            out.push(b'\n');
        }
        _ => return Err(gnunet_types::Error::Malformed.into()),
    }
    Ok(())
}

fn write_peer(out: &mut Vec<u8>, peer: &[u8; 32], prefix: usize) -> Result<(), Cause> {
    let mut encoded = [0; 52];
    let length = gnunet_gnsrecord::encode_base32(peer, &mut encoded)?;
    out.extend_from_slice(&encoded[..prefix.min(length)]);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use gnunet_wire::official::cadet::PeerIdentities;

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Checks exact official display bytes"
    )]
    fn renders_official_peer_tunnel_and_path_lines() -> Result<(), Cause> {
        let peer = [0; 32];
        let label = "0".repeat(52);
        let mut output = Vec::new();
        row(
            &mut output,
            Response::PeerInfo {
                paths: 2,
                tunnel: 1,
                best_path_length: 4,
                peer,
            },
        )?;
        assert_eq!(output, format!("{label} tunnel: Y, paths: 2\n").as_bytes());
        row(
            &mut output,
            Response::TunnelInfo {
                channels: 1,
                peer,
                connections: 2,
                encryption_state: 3,
                connection_state: 0,
            },
        )?;
        assert_eq!(
            output,
            format!("{label} [ENC: READY, CON: NEW  ] CHs: 1, CONNs: 2\n").as_bytes()
        );
        let peers = [peer, [255; 32]];
        row(
            &mut output,
            Response::PathInfo {
                offset: 1,
                peers: PeerIdentities::new(&peers),
            },
        )?;
        assert_eq!(output, b"Path of length 2: 0000 *ZZZZ* \n");
        Ok(())
    }
}
