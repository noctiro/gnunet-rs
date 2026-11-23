//! Original operation settlement without discarding another control's deadline.
use super::{Intent, phone};

pub(super) fn complete(intent: &mut Option<Intent>, operation: &phone::Operation) {
    if intent
        .as_ref()
        .is_some_and(|pending| pending.operation.as_ref() == Some(operation))
    {
        *intent = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::run::state::Action;
    use gnunet_service_runtime::clock::{Bounds, SystemClock};
    use std::{path::PathBuf, sync::Arc, time::Duration};

    #[test]
    #[expect(
        clippy::panic_in_result_fn,
        reason = "Actual SDK operation identities must preserve unrelated control ownership and its fixed deadline"
    )]
    fn another_operation_cannot_retire_an_admitted_or_waiting_control()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let _entered = runtime.enter();
        let source = phone::EndpointSource::unix_with_clock(
            PathBuf::from("unused-conversation-receipt-source"),
            Arc::new(SystemClock),
        );
        let bounds = Bounds::after(source.clock().as_ref(), Duration::from_secs(60))?;
        // Constructors mint real opaque domains/operations without opening IPC.
        // The matching rule depends on identity, independently of frame kind.
        let first = phone::Line::register(
            source.duplicate()?,
            &[7; 64],
            phone::Limits::default(),
            bounds,
        )?;
        let second = phone::Line::register(source, &[7; 64], phone::Limits::default(), bounds)?;
        let original = first.initializer().operation;
        let unrelated = second.initializer().operation;
        assert_ne!(original, unrelated);
        let alarm = tokio::time::Instant::now() + Duration::from_secs(30);
        let mut intent = Some(Intent {
            action: Action::Suspend,
            bounds,
            operation: Some(original.clone()),
            alarm: Box::pin(tokio::time::sleep_until(alarm)),
        });

        complete(&mut intent, &unrelated);
        let pending = intent.as_ref().ok_or("unrelated receipt erased control")?;
        assert_eq!(pending.operation.as_ref(), Some(&original));
        assert!(matches!(pending.action, Action::Suspend));
        assert_eq!(pending.bounds.hard(), bounds.hard());
        assert_eq!(pending.bounds.expires(), bounds.expires());
        assert_eq!(pending.alarm.deadline(), alarm);
        complete(&mut intent, &original);
        assert!(intent.is_none());

        intent = Some(Intent {
            action: Action::Cancel,
            bounds,
            operation: None,
            alarm: Box::pin(tokio::time::sleep_until(alarm)),
        });
        complete(&mut intent, &original);
        let waiting = intent
            .as_ref()
            .ok_or("receipt erased unsubmitted control")?;
        assert!(waiting.operation.is_none());
        assert_eq!(waiting.bounds.hard(), bounds.hard());
        assert_eq!(waiting.alarm.deadline(), alarm);
        Ok(())
    }
}
