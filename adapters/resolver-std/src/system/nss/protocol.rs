//! Official RESOLVER frames on the NSS worker's stdin and stdout.
use super::super::{ANSWERS_PER_QUESTION, Answer, Question};
use crate::startup::native_family;
use gnunet_client::resolver::{
    Family, Query, REQUEST_LEN, RESPONSE_LEN, Reply, Request, Response, WireId, encode_response,
};
use gnunet_dns::{MAX_LABEL_LENGTH, MAX_NAME_LENGTH};
use gnunet_wire::official::Frame;
use std::{
    io::{self, Write},
    net::IpAddr,
};

// A worker handles one question. The parent observes both successful exit
// and EOF. All responses use the same fixed ID, including the final END.
const WORKER_ID: WireId = WireId([0; 4]);
pub(super) const MAX_QUERY_BYTES: usize = REQUEST_LEN + MAX_NAME_LENGTH + 2;
pub(super) const MAX_REPLY_BYTES: usize =
    ANSWERS_PER_QUESTION * (RESPONSE_LEN + MAX_NAME_LENGTH + 1) + RESPONSE_LEN;

pub(super) fn encode_question(question: Question<'_>, output: &mut [u8]) -> io::Result<usize> {
    let profile = native_family().map_err(wire_error)?;
    let (family, name) = match question {
        Question::A(name) => (Family::V4, name),
        Question::Aaaa(name) => (Family::V6, name),
        Question::Any(name) => (Family::Any, name),
        Question::Ptr(address) => {
            return Request::reverse(WORKER_ID, address)
                .encode(profile, output)
                .map_err(wire_error);
        }
    };
    let name = validate_query_name(name.as_bytes())?;
    Request::forward(WORKER_ID, family, name.as_bytes())
        .and_then(|request| request.encode(profile, output))
        .map_err(wire_error)
}

pub(super) fn read_question(bytes: &[u8]) -> io::Result<Question<'_>> {
    if bytes.len() > MAX_QUERY_BYTES {
        return Err(invalid("NSS question exceeds its byte limit"));
    }
    let profile = native_family().map_err(wire_error)?;
    let frame = Frame::decode(bytes).map_err(wire_error)?;
    let request = Request::decode(frame, profile).map_err(wire_error)?;
    if request.id() != WORKER_ID {
        return Err(invalid("unexpected NSS question ID"));
    }
    match request.query() {
        Query::Forward { family, hostname } => {
            let name = validate_query_name(hostname)?;
            Ok(match family {
                Family::V4 => Question::A(name),
                Family::V6 => Question::Aaaa(name),
                Family::Any => Question::Any(name),
            })
        }
        Query::Reverse(address) if request.raw_direction() == 1 => Ok(Question::Ptr(address)),
        Query::Reverse(_) => Err(invalid("unexpected NSS question direction")),
    }
}

pub(super) fn write_reply(
    mut output: impl Write,
    outcome: io::Result<Vec<Answer>>,
) -> io::Result<()> {
    let answers = outcome?;
    if answers.len() > ANSWERS_PER_QUESTION {
        return Err(invalid("too many NSS answers"));
    }

    let mut bytes = [0; MAX_REPLY_BYTES];
    let mut remaining = bytes.as_mut_slice();
    for answer in &answers {
        let reply = match answer {
            Answer::V4(address) => Reply::Address(IpAddr::V4(*address)),
            Answer::V6(address) => Reply::Address(IpAddr::V6(*address)),
            Answer::Name(name) => Reply::Hostname(validate_name(name.as_bytes())?),
        };
        let size = encode_response(WORKER_ID, reply, remaining).map_err(wire_error)?;
        remaining = &mut remaining[size..];
    }
    let end = encode_response(WORKER_ID, Reply::End, remaining).map_err(wire_error)?;
    let size = MAX_REPLY_BYTES - remaining.len() + end;
    output.write_all(&bytes[..size])?;
    output.flush()
}

pub(super) fn read_reply(
    mut bytes: &[u8],
    question: Question<'_>,
    limit: usize,
) -> io::Result<Vec<Answer>> {
    if bytes.len() > MAX_REPLY_BYTES {
        return Err(invalid("NSS reply exceeds its byte limit"));
    }
    let limit = limit.min(ANSWERS_PER_QUESTION);
    let mut answers = Vec::new();
    loop {
        let (frame, remaining) = Frame::decode_prefix(bytes).map_err(wire_error)?;
        let response = Response::decode(frame).map_err(wire_error)?;
        if response.id() != WORKER_ID {
            return Err(invalid("unexpected NSS reply ID"));
        }
        if response.is_end() {
            return if remaining.is_empty() {
                Ok(answers)
            } else {
                Err(invalid("data follows the NSS END response"))
            };
        }
        if answers.len() == limit {
            return Err(invalid("too many NSS answers"));
        }
        let answer = match question {
            Question::A(_) => read_address(response, Family::V4)?,
            Question::Aaaa(_) => read_address(response, Family::V6)?,
            Question::Any(_) => read_address(response, Family::Any)?,
            Question::Ptr(_) => {
                let name = response
                    .payload()
                    .strip_suffix(b"\0")
                    .ok_or_else(|| invalid("unterminated NSS name"))?;
                let text = std::str::from_utf8(validate_name(name)?)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
                let mut name = String::new();
                name.try_reserve_exact(text.len())
                    .map_err(io::Error::other)?;
                name.push_str(text);
                Answer::Name(name)
            }
        };
        answers.try_reserve(1).map_err(io::Error::other)?;
        answers.push(answer);
        bytes = remaining;
    }
}

fn read_address(response: Response<'_>, family: Family) -> io::Result<Answer> {
    let address = response
        .address()
        .map_err(wire_error)?
        .filter(|address| family.accepts(*address))
        .ok_or_else(|| invalid("unexpected NSS address family"))?;
    match address {
        IpAddr::V4(address) => Ok(Answer::V4(address)),
        IpAddr::V6(address) => Answer::unscoped_ipv6(address.octets())
            .ok_or_else(|| invalid("scoped IPv6 address in NSS reply")),
    }
}

fn validate_query_name(bytes: &[u8]) -> io::Result<&str> {
    let labels = bytes.strip_suffix(b".").unwrap_or(bytes);
    if bytes.is_empty()
        || labels.len() > MAX_NAME_LENGTH
        || bytes
            .iter()
            .any(|byte| !byte.is_ascii_graphic() || *byte == b'\\')
        || (!labels.is_empty()
            && labels
                .split(|byte| *byte == b'.')
                .any(|label| label.is_empty() || label.len() > MAX_LABEL_LENGTH))
    {
        return Err(invalid("invalid NSS question name"));
    }
    std::str::from_utf8(bytes).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

fn validate_name(bytes: &[u8]) -> io::Result<&[u8]> {
    if bytes.is_empty() || bytes.len() > MAX_NAME_LENGTH || bytes.contains(&0) {
        return Err(invalid("invalid NSS name length or terminator"));
    }
    Ok(bytes)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn wire_error(error: gnunet_types::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check exact question framing and hostname boundaries"
    )]
    fn questions_keep_search_policy_and_require_one_exact_frame() -> io::Result<()> {
        let mut bytes = [0; MAX_QUERY_BYTES];
        let size = encode_question(Question::Any("host"), &mut bytes)?;
        assert!(matches!(
            read_question(&bytes[..size])?,
            Question::Any("host")
        ));
        assert!(read_question(&bytes[..size - 1]).is_err());
        assert!(read_question(&bytes[..size + 1]).is_err());
        bytes[REQUEST_LEN + 1] = 0;
        assert!(read_question(&bytes[..size]).is_err());

        let size = encode_question(Question::Aaaa("example.test."), &mut bytes)?;
        assert!(matches!(
            read_question(&bytes[..size])?,
            Question::Aaaa("example.test.")
        ));
        let address = IpAddr::V6(Ipv6Addr::LOCALHOST);
        let size = encode_question(Question::Ptr(address), &mut bytes)?;
        assert!(matches!(read_question(&bytes[..size])?, Question::Ptr(value) if value == address));

        for name in ["", "a\\b", "a\0b", "a..b", "ünicode.test"] {
            assert!(encode_question(Question::A(name), &mut bytes).is_err());
        }
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check exact worker response boundaries"
    )]
    fn accepts_only_one_complete_response_stream() -> io::Result<()> {
        let address = Ipv4Addr::new(192, 0, 2, 1);
        let question = Question::A("example.test");
        let mut bytes = Vec::new();
        write_reply(&mut bytes, Ok(vec![Answer::V4(address)]))?;
        assert!(read_reply(&bytes, question, 1)?.as_slice() == [Answer::V4(address)]);
        assert!(read_reply(&bytes, Question::Aaaa("example.test"), 1).is_err());
        assert!(read_reply(&bytes, question, 0).is_err());
        assert!(read_reply(&bytes[..bytes.len() - RESPONSE_LEN], question, 1).is_err());
        bytes.push(0);
        assert!(read_reply(&bytes, question, 1).is_err());

        bytes.clear();
        let mixed = vec![Answer::V6(Ipv6Addr::LOCALHOST), Answer::V4(address)];
        write_reply(&mut bytes, Ok(mixed))?;
        assert!(
            read_reply(&bytes, Question::Any("example.test"), 2)?.as_slice()
                == [Answer::V6(Ipv6Addr::LOCALHOST), Answer::V4(address)]
        );

        bytes.clear();
        write_reply(&mut bytes, Ok(Vec::new()))?;
        assert_eq!(bytes.len(), RESPONSE_LEN);
        assert!(read_reply(&bytes, question, 0)?.is_empty());
        bytes[4] = 1;
        assert!(read_reply(&bytes, question, 0).is_err());
        Ok(())
    }

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Check name bounds and worker errors"
    )]
    fn names_remain_exact_and_failed_lookups_emit_nothing() -> io::Result<()> {
        let question = Question::Ptr(Ipv4Addr::new(192, 0, 2, 1).into());
        let mut bytes = Vec::new();
        let name = "example.test";
        write_reply(&mut bytes, Ok(vec![Answer::Name(name.into())]))?;
        assert!(read_reply(&bytes, question, 1)?.as_slice() == [Answer::Name(name.into())]);
        bytes[RESPONSE_LEN] = 0xff;
        assert!(read_reply(&bytes, question, 1).is_err());
        bytes[RESPONSE_LEN] = 0;
        assert!(read_reply(&bytes, question, 1).is_err());

        bytes.clear();
        let oversized = "x".repeat(MAX_NAME_LENGTH + 1);
        assert!(write_reply(&mut bytes, Ok(vec![Answer::Name(oversized)])).is_err());
        assert!(
            write_reply(&mut bytes, Err(io::ErrorKind::TimedOut.into()))
                .is_err_and(|error| error.kind() == io::ErrorKind::TimedOut)
        );
        assert!(bytes.is_empty());
        Ok(())
    }
}
