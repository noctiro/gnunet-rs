//! Numbered TESTBED nodes and bounded sparse aggregation of their statistics.

use super::{
    Failure,
    driver::{self, Bound, Connection, Errors, Failed, Inputs, Report},
    finite::{self, Action, Destination, Node},
    output::Output,
};
use crate::foreground::Signals;
use gnunet_client::statistics::{Selector, Statistic};
use gnunet_config::{Configuration, ProjectData};
use std::{
    collections::BTreeMap,
    fs,
    future::{Future, poll_fn},
    path::{Path, PathBuf},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::{Instant, Sleep};

const MAX_NODES: usize = 256;
const MAX_ENTRIES: usize = 16_384;
const MAX_ROWS: usize = 65_536;
const MAX_LABEL_BYTES: usize = 8 * 1024 * 1024;
const MAX_VALUES: usize = 524_288;
const DEADLINE: Duration = Duration::from_secs(60);
const OUTPUT_RETRY: Duration = Duration::from_millis(10);

fn discover(root: &Path, deadline: Instant) -> Result<Vec<PathBuf>, Failure> {
    let mut entries = 0;
    let mut nodes = Vec::new();
    let mut next_entry = || -> Result<(), Failure> {
        entries += 1;
        if entries > MAX_ENTRIES {
            return Err("TESTBED directory entry limit exceeded".into());
        }
        if Instant::now() >= deadline {
            return Err("TESTBED deadline during directory discovery".into());
        }
        Ok(())
    };
    for entry in fs::read_dir(root)? {
        next_entry()?;
        let entry = entry?;
        let Some(number) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<u32>().ok())
        else {
            continue;
        };
        let directory = entry.path();
        if !directory.is_dir() {
            continue;
        }
        let mut selected = None::<PathBuf>;
        for config in fs::read_dir(&directory)? {
            next_entry()?;
            let config = config?;
            if config.file_name().as_encoded_bytes().starts_with(b"config") {
                let path = config.path();
                if path.is_file() && selected.as_ref().is_none_or(|current| path < *current) {
                    selected = Some(path);
                }
            }
        }
        if let Some(path) = selected {
            if nodes.len() == MAX_NODES {
                return Err("TESTBED node limit exceeded".into());
            }
            nodes.try_reserve(1)?;
            nodes.push((number, path));
        }
    }
    nodes.sort_unstable();
    Ok(nodes.into_iter().map(|(_, path)| path).collect())
}

struct Row {
    subsystem_len: usize,
    persistent: bool,
    values: Vec<(usize, u64)>,
}
impl Row {
    fn columns(&self, node_count: usize) -> impl Iterator<Item = u64> + '_ {
        let mut values = self.values.iter().copied().peekable();
        (0..node_count).map(move |node| {
            values
                .next_if(|&(column, _)| column == node)
                .map_or(0, |(_, value)| value)
        })
    }
}

#[derive(Default)]
struct Table {
    // The wire separates names with NUL and excludes it from both names.
    rows: BTreeMap<Vec<u8>, Row>,
    key: Vec<u8>,
    label_bytes: usize,
    values: usize,
}
impl Table {
    fn record(&mut self, node: usize, value: Statistic<'_>) -> Result<(), Failure> {
        let Selector { subsystem, name } = value.selector;
        self.key.clear();
        self.key
            .try_reserve_exact(subsystem.len() + 1 + name.len())?;
        self.key.extend_from_slice(subsystem);
        self.key.push(0);
        self.key.extend_from_slice(name);
        if let Some(row) = self.rows.get_mut(self.key.as_slice()) {
            if let Some((last, saved)) = row.values.last_mut()
                && *last == node
            {
                *saved = value.value;
                return Ok(());
            }
            push_value(&mut self.values, &mut row.values, node, value.value)?;
        } else {
            let label_bytes = self.label_bytes + self.key.len();
            if self.rows.len() == MAX_ROWS || label_bytes > MAX_LABEL_BYTES {
                return Err("TESTBED statistic label limit exceeded".into());
            }
            let mut key = Vec::new();
            key.try_reserve_exact(self.key.len())?;
            key.extend_from_slice(&self.key);
            let mut values = Vec::new();
            push_value(&mut self.values, &mut values, node, value.value)?;
            let _previous = self.rows.insert(
                key,
                Row {
                    subsystem_len: subsystem.len(),
                    persistent: value.persistent(),
                    values,
                },
            );
            self.label_bytes = label_bytes;
        }
        Ok(())
    }
}

fn push_value(
    used: &mut usize,
    values: &mut Vec<(usize, u64)>,
    node: usize,
    value: u64,
) -> Result<(), Failure> {
    if *used == MAX_VALUES {
        return Err("TESTBED statistic value limit exceeded".into());
    }
    values.try_reserve(1)?;
    values.push((node, value));
    *used += 1;
    Ok(())
}

pub(super) async fn command(
    inputs: Inputs,
    path: &Path,
    action: Action,
) -> Result<Report, Failure> {
    let Inputs {
        selector,
        style,
        parent,
        connection,
        mut resolver,
    } = inputs;
    let mut bound = Bound::new(DEADLINE)?;
    let mut signals = Signals::new(parent)?;
    poll_fn(|cx| Poll::Ready(guard(cx, &mut bound, &connection, &mut signals))).await?;
    let nodes = discover(path, bound.hard)?;
    let mut table = Table::default();
    let mut report = Report::default();
    for (index, path) in nodes.iter().enumerate() {
        poll_fn(|cx| Poll::Ready(guard(cx, &mut bound, &connection, &mut signals))).await?;
        let mut config =
            Configuration::create(Arc::new(ProjectData::default()), Default::default())?;
        config
            .load(Some(path))
            .map_err(|error| format!("TESTBED configuration {}: {error}", path.display()))?;
        poll_fn(|cx| Poll::Ready(guard(cx, &mut bound, &connection, &mut signals))).await?;
        connection.live.replace(config)?;
        resolver.context().connect_live(connection.live.clone())?;
        let mut record = |statistic: Statistic<'_>| table.record(index, statistic);
        let destination = match action {
            Action::Get => Destination::Collect(&mut record),
            Action::Set { .. } => Destination::Silent,
        };
        let complete = finite::node(
            Node {
                selector: &selector,
                connection: &connection,
                signals: &mut signals,
                resolver: &mut resolver,
                deadline: Some(bound.hard),
            },
            action,
            destination,
        )
        .await
        .map_err(|error| format!("TESTBED node {}: {error}", path.display()))?;
        report.notifications = report.notifications.saturating_add(complete.notifications);
        report.epochs = report.epochs.saturating_add(complete.epochs);
        report.connect_retries = report
            .connect_retries
            .saturating_add(complete.connect_retries);
        report.physical_drop = complete.physical_drop;
    }
    if !table.rows.is_empty() {
        let mut output = Output::new(style, finite::OUTPUT)?;
        let result = emit(
            table,
            nodes.len(),
            &mut output,
            &mut bound,
            &connection,
            &mut signals,
            &mut report,
        )
        .await;
        (report.output_prefix, report.output_total) = output.pending();
        let errors = Errors {
            original: result.err(),
            stdout_flush: output.flush().err(),
            deadline: bound.expired(),
            ..Errors::default()
        };
        if errors.failed() {
            return Err(Box::new(Failed { errors, report }));
        }
    }
    Ok(report)
}

fn guard(
    cx: &mut Context<'_>,
    bound: &mut Bound,
    connection: &Connection,
    signals: &mut Signals,
) -> Result<(), Failure> {
    if bound.guard(cx) {
        return Err("TESTBED statistics deadline expired".into());
    }
    if driver::stop(cx, signals, &connection.reports, &connection.stop)? {
        return Err("TESTBED statistics cancelled".into());
    }
    Ok(())
}

async fn emit(
    table: Table,
    node_count: usize,
    output: &mut Output,
    bound: &mut Bound,
    connection: &Connection,
    signals: &mut Signals,
    report: &mut Report,
) -> Result<(), Failure> {
    for (key, row) in table.rows {
        let (subsystem, name) = key.split_at(row.subsystem_len);
        output.stage_columns(
            Selector {
                subsystem,
                name: &name[1..],
            },
            row.persistent,
            row.columns(node_count),
        )?;
        let mut retry: Option<Pin<Box<Sleep>>> = None;
        poll_fn(|cx| {
            guard(cx, bound, connection, signals)?;
            if retry
                .as_mut()
                .is_some_and(|wait| wait.as_mut().poll(cx).is_pending())
            {
                return Poll::Pending;
            }
            match output.step()? {
                Some(true) => Poll::Ready(Ok::<(), Failure>(())),
                Some(false) => {
                    retry = None;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
                None => {
                    retry = Some(Box::pin(tokio::time::sleep(OUTPUT_RETRY)));
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        })
        .await?;
        output.release();
        report.rows_written += 1;
        tokio::task::consume_budget().await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn testbed_sparse_statistics_keep_node_columns_and_zero_fill() -> Result<(), Failure> {
        let mut table = Table::default();
        let selector = Selector {
            subsystem: b"core",
            name: b"peers",
        };
        table.record(
            0,
            Statistic {
                raw_uid: 0x8000_0001,
                value: 2,
                selector,
            },
        )?;
        table.record(
            2,
            Statistic {
                raw_uid: 2,
                value: 5,
                selector,
            },
        )?;
        table.record(
            2,
            Statistic {
                raw_uid: 2,
                value: 8,
                selector,
            },
        )?;
        let row = table
            .rows
            .get(b"core\0peers".as_slice())
            .ok_or("missing statistic")?;
        assert_eq!(row.columns(4).collect::<Vec<_>>(), [2, 0, 8, 0]);
        assert!(row.persistent);
        assert_eq!(table.values, 2);
        Ok(())
    }

    #[test]
    fn testbed_discovery_selects_numbered_configs_in_node_order() -> Result<(), Failure> {
        struct Directory(PathBuf);
        impl Drop for Directory {
            fn drop(&mut self) {
                let _cleanup = fs::remove_dir_all(&self.0);
            }
        }
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
        let path =
            std::env::temp_dir().join(format!("gn-stat-testbed-{}-{nonce:x}", std::process::id()));
        fs::create_dir(&path)?;
        let directory = Directory(path);
        for node in ["10", "2", "ignore", "4"] {
            fs::create_dir(directory.0.join(node))?;
        }
        for name in [
            "2/config-a",
            "2/config-z",
            "10/config",
            "ignore/config",
            "4/other",
        ] {
            fs::write(directory.0.join(name), b"")?;
        }
        let nodes = discover(&directory.0, Instant::now() + Duration::from_secs(1))?;
        assert_eq!(
            nodes,
            [
                directory.0.join("2/config-a"),
                directory.0.join("10/config")
            ]
        );
        Ok(())
    }
}
