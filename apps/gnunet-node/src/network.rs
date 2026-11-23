use gnunet_node_host::{NetworkChangeNotifier, NetworkChanges, network_changes};
use gnunet_service_runtime::network_change::RouteMonitor;
use std::{
    io::{self, Write},
    task::{Context, Poll},
};

pub(super) struct Watch {
    route: Option<(RouteMonitor, NetworkChangeNotifier)>,
}

impl Watch {
    pub(super) fn start() -> io::Result<(Self, NetworkChanges)> {
        match RouteMonitor::subscribe() {
            Ok(source) => {
                let (notifier, changes) = network_changes();
                Ok((
                    Self {
                        route: Some((source, notifier)),
                    },
                    changes,
                ))
            }
            Err(error) if RouteMonitor::is_unavailable(&error) => {
                route_diagnostic(&error);
                Ok((Self { route: None }, NetworkChanges::default()))
            }
            Err(error) => Err(error),
        }
    }

    pub(super) fn poll(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        if let Some((source, notifier)) = &mut self.route {
            match source.poll_changed(cx) {
                Poll::Ready(Ok(())) => {
                    notifier.notify();
                    // The stop future stays pending, so poll again to arm the next wait.
                    cx.waker().wake_by_ref();
                }
                Poll::Ready(Err(error)) => {
                    notifier.notify();
                    route_diagnostic(&error);
                    return self.close();
                }
                Poll::Pending => {}
            }
        }
        Ok(())
    }

    pub(super) fn close(&mut self) -> io::Result<()> {
        if let Some((source, _)) = &mut self.route {
            source.close()?;
        }
        self.route = None;
        Ok(())
    }
}

fn route_diagnostic(error: &io::Error) {
    let _reported = writeln!(
        io::stderr().lock(),
        "gnunet-node: route notifications unavailable, retaining interface scan timers: {error}"
    );
}
