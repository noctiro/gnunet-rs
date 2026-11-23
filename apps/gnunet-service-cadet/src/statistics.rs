//! Native STATISTICS publication for the CADET daemon.
use gnunet_cadet_host::startup::statistics::{
    COUNT, GAUGES, NAMES, Publisher, PublisherContext, Snapshot,
};
use gnunet_ipc_unix::{
    handle::Instance,
    producer::{self, Metric, Producer, Progress},
};
use gnunet_program_host::reporting::Reporter;
use std::{
    error::Error,
    fmt,
    task::{Context, Poll},
    time::Duration,
};

const fn definitions() -> [Metric; COUNT] {
    let mut metrics = [Metric::counter(b"", false); COUNT];
    let mut index = 0;
    while index < COUNT {
        metrics[index] = if GAUGES[index] {
            Metric::gauge(NAMES[index], false)
        } else {
            Metric::counter(NAMES[index], false)
        };
        index += 1;
    }
    metrics
}

static METRICS: [Metric; COUNT] = definitions();

fn snapshot(actual: Snapshot) -> producer::Snapshot<COUNT> {
    producer::Snapshot::new(*actual.values(), actual.overflowed())
}

pub(super) fn limits(operation: Duration) -> producer::Limits {
    producer::Limits {
        operation,
        ..Default::default()
    }
}

pub(super) fn publisher<'id>(
    instance: &'id mut Instance,
    context: PublisherContext,
    reports: Reporter,
) -> Result<Box<dyn Publisher + 'id>, Box<dyn Error>> {
    let producer = Producer::new(
        instance,
        context.live,
        context.resolution,
        context.clock,
        producer::Configuration {
            subsystem: b"cadet",
            metrics: &METRICS,
            initial: snapshot(context.initial),
            limits: limits(context.operation),
        },
    )?;
    Ok(Box::new(Native { producer, reports }))
}

struct Native<'id> {
    producer: Producer<'id, COUNT>,
    reports: Reporter,
}

impl Publisher for Native<'_> {
    fn refresh(&mut self, actual: Snapshot) -> Result<(), Box<dyn Error>> {
        self.producer.refresh(snapshot(actual))?;
        Ok(())
    }

    fn poll_native_guard(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Box<dyn Error>>> {
        self.producer.poll_native_guard(cx).map(|result| {
            result?;
            Ok(())
        })
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Box<dyn Error>>> {
        self.producer.poll(cx, None).map(|result| {
            if let Progress::Written { counter, value } = result? {
                self.reports.debug(
                    "cadet.statistics.written",
                    format_args!(
                        "CADET wrote local statistics frame counter={counter} value={value:?}"
                    ),
                );
            }
            Ok(())
        })
    }

    fn begin_close(&mut self, actual: Snapshot, grace: Duration) -> Result<(), Box<dyn Error>> {
        self.producer
            .begin_close(snapshot(actual), grace)
            .map_err(Into::into)
    }

    fn abort(&mut self) -> Result<(), Box<dyn Error>> {
        self.producer.abort().map_err(Into::into)
    }

    fn is_closed(&self) -> bool {
        self.producer.is_closed()
    }

    fn report(&self) -> Box<dyn fmt::Debug> {
        Box::new(self.producer.report())
    }
}
