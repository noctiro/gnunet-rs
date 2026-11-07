//! Pure source cases only: no codec, entropy, audio device or helper is invoked.
use super::{Error, Limits, framing, ogg};
use gnunet_types::Error as Fault;
use std::io::Cursor;
fn check(value: bool) -> Result<(), Error> {
    if value {
        Ok(())
    } else {
        Err(Fault::Malformed.into())
    }
}
#[test]
fn helper_frames_do_not_define_ogg_boundaries() -> Result<(), Error> {
    let limits = Limits::default();
    let mut mux = ogg::Mux::new(7, limits)?;
    let page = mux.packet(&[42; 255], 0, 1920)?.to_vec();
    let decoded = ogg::Page::decode(&page, limits)?;
    check(decoded.laces() == [255, 0])?;
    let mut pipe = Vec::new();
    for chunk in page.chunks(7) {
        framing::write_frame(&mut pipe, chunk, limits)?;
    }
    let mut input = framing::Input::new(Cursor::new(pipe), limits)?;
    let mut pages = ogg::Pages::new(limits)?;
    let mut seen = 0;
    while let Some(payload) = input.next_frame()? {
        let mut at = 0;
        loop {
            let (used, status) = pages.feed(&payload[at..])?;
            at += used;
            match status {
                ogg::Status::Ready => {
                    check(pages.page()?.body() == [42; 255])?;
                    seen += 1;
                    pages.consume()?;
                }
                ogg::Status::NeedInput if at == payload.len() => break,
                ogg::Status::NeedInput | ogg::Status::Resynchronized => {}
            }
            if at == payload.len() && status == ogg::Status::Ready {
                break;
            }
        }
    }
    pages.finish()?;
    check(seen == 1)
}
#[test]
fn partial_helper_header_and_partial_page_are_not_eof_success() -> Result<(), Error> {
    let limits = Limits::default();
    let mut input = framing::Input::new(Cursor::new([0, 7]), limits)?;
    check(matches!(
        input.next_frame(),
        Err(Error::Truncated {
            actual: 2,
            expected: 4,
            ..
        })
    ))?;
    let mut pages = ogg::Pages::new(limits)?;
    let _progress = pages.feed(b"Ogg")?;
    check(matches!(pages.finish(), Err(Error::Truncated { .. })))
}
#[test]
fn damaged_crc_is_a_real_error_not_a_synthetic_packet() -> Result<(), Error> {
    let limits = Limits::default();
    let mut mux = ogg::Mux::new(3, limits)?;
    let mut page = mux.packet(&[1, 2, 3], 0, 1920)?.to_vec();
    let last = page.last_mut().ok_or(Fault::Truncated)?;
    *last ^= 1;
    check(matches!(
        ogg::Page::decode(&page, limits),
        Err(Error::Checksum)
    ))
}
