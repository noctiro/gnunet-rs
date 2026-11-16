//! Sequential official backup traversal and validated one-shot insertion.
use super::{
    buffer,
    driver::Driver,
    outcome::{Diagnostic, RejectedStatus},
};
use crate::{
    Failure,
    format::{self, Record},
    stream::{self, Stream},
};
use gnunet_datastore_host::{Outcome, Request, Response};
use gnunet_program_host::policy::Level;
use gnunet_wire::official::datastore::MAX_VALUE_BYTES;
use zeroize::{Zeroize, Zeroizing};
pub(super) async fn work(
    driver: &mut Driver<'_, '_, '_, '_>,
    dump: bool,
    insert: bool,
    path: Option<&std::path::Path>,
    retained: stream::Retained,
) -> Result<(), Failure> {
    if dump {
        let mut budget = driver.budget()?;
        driver.check(&mut budget).await?;
        let mut output = Stream::output(path, retained.clone())?;
        output
            .write_all(driver, &mut budget, &format::MAGIC, "dump magic")
            .await?;
        loop {
            let mut budget = driver.budget()?;
            let next_uid = driver.report.next_uid;
            let taken = driver
                .operation(
                    Request::Get {
                        key: None,
                        kind: 0,
                        next_uid,
                        random: false,
                    },
                    &mut budget,
                )
                .await?;
            match (taken.completion.outcome, taken.response()?) {
                (Outcome::Data { uid }, Some(Response::Data(data))) if uid == data.uid => {
                    if uid < next_uid {
                        return Err("actual DATA UID did not advance the original cursor".into());
                    }
                    let next = uid.checked_add(1).ok_or("actual DATA UID overflow")?;
                    let header = Record::from_data(data)?.encode()?;
                    output
                        .write_all(driver, &mut budget, &header, "dump record header")
                        .await?;
                    output
                        .write_all(driver, &mut budget, data.value, "dump record body")
                        .await?;
                    driver.report.dumped = driver
                        .report
                        .dumped
                        .checked_add(1)
                        .ok_or("dumped count overflow")?;
                    driver.report.next_uid = next;
                }
                (Outcome::NotFound, Some(Response::End)) => break,
                _ => {
                    return Err(format!(
                        "original dump operation did not return DATA/END; completion={:?}",
                        driver.report.last
                    )
                    .into());
                }
            }
        }
        output.finish().await?;
        driver.reports.message(
            Level::INFO,
            "datastore.dump.complete",
            format_args!("Dumped {} records", driver.report.dumped),
        );
    }
    if insert {
        let mut budget = driver.budget()?;
        driver.check(&mut budget).await?;
        let mut input = Stream::input(path, retained)?;
        let mut magic = [0; 16];
        input
            .read_exact(driver, &mut budget, &mut magic, false, "input magic")
            .await?;
        if magic != format::MAGIC {
            return Err("input is not GNUNETDATASTORE1".into());
        }
        let mut value = buffer(MAX_VALUE_BYTES)?;
        loop {
            let mut budget = driver.budget()?;
            let mut header = [0; format::HEADER];
            if !input
                .read_exact(
                    driver,
                    &mut budget,
                    &mut header,
                    true,
                    "input record header",
                )
                .await?
            {
                break;
            }
            let record = Record::decode(&header)?;
            value.as_mut_slice().zeroize();
            input
                .read_exact(
                    driver,
                    &mut budget,
                    &mut value[..record.size],
                    false,
                    "input record body",
                )
                .await?;
            let taken = driver
                .operation(
                    Request::Put(record.put(&value[..record.size])?),
                    &mut budget,
                )
                .await?;
            match (taken.completion.outcome, taken.response()?) {
                (
                    Outcome::Status {
                        code,
                        min_expiration,
                    },
                    Some(Response::Status(status)),
                ) if code == status.code && min_expiration == status.min_expiration => {
                    if code < 0 {
                        let diagnostic = if let Some(bytes) = status.message {
                            let mut owned = Vec::new();
                            owned.try_reserve_exact(bytes.len())?;
                            owned.extend_from_slice(bytes);
                            Some(Diagnostic(Zeroizing::new(owned)))
                        } else {
                            None
                        };
                        return Err(Box::new(RejectedStatus {
                            code,
                            min_expiration: min_expiration.as_micros(),
                            diagnostic,
                        }));
                    }
                    driver.report.inserted = driver
                        .report
                        .inserted
                        .checked_add(1)
                        .ok_or("insert count overflow after actual successful STATUS")?;
                }
                _ => {
                    return Err(format!(
                        "original PUT has no successful actual STATUS; completion={:?}",
                        driver.report.last
                    )
                    .into());
                }
            }
            value.as_mut_slice().zeroize();
        }
        input.finish().await?;
        driver.reports.message(
            Level::INFO,
            "datastore.insert.complete",
            format_args!("Inserted {} records", driver.report.inserted),
        );
    }
    Ok(())
}
