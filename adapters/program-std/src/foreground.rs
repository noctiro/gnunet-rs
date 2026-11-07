//! One original foreground future survives PROGRAM task/scheduler cancellation.
//! The caller retains its own stop latch and actual cleanup/deadline contract.
use crate::{
    program::{self, Prepared},
    shared_clock::SharedClock,
};
use std::{
    cell::{Cell, RefCell},
    error::Error,
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    rc::Rc,
    task::Poll,
};
type Cause = Box<dyn Error>;
struct Original<F: Future> {
    future: Pin<Box<F>>,
    result: Option<F::Output>,
}
/// All independent terminal facts, including a successful product cleanup when
/// PROGRAM itself failed. No scheduler exit is a fabricated product completion.
struct Failure<T: fmt::Debug> {
    program: Option<Cause>,
    admission: Option<program::Failure>,
    task: Option<Cause>,
    completion: Option<T>,
}
impl<T: fmt::Debug> fmt::Debug for Failure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Failure")
            .field("program", &self.program)
            .field("admission", &self.admission)
            .field("task", &self.task)
            .field("completion", &self.completion)
            .finish()
    }
}
impl<T: fmt::Debug> fmt::Display for Failure<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PROGRAM foreground lifecycle: {self:?}")
    }
}
impl<T: fmt::Debug + 'static> Error for Failure<T> {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.program
            .as_deref()
            .or_else(|| self.admission.as_ref().map(|error| error as &dyn Error))
            .or(self.task.as_deref())
    }
}
/// Run one caller-owned foreground through the shared PROGRAM scheduler.
///
/// Scheduler failure sets the same stop latch and continues polling the exact
/// original future to its real terminal result. The caller must observe that
/// latch before new effects and drive its original bounded cleanup. This helper
/// creates no replacement future, clock, Resolver or proof of physical closure.
/// Independent scheduler/admission/task errors and successful cleanup reports
/// remain available together through the returned owned error.
pub async fn run<const REQUESTS: usize, const ANSWERS: usize, F, T>(
    prepared: Prepared,
    context: &mut gnunet_resolver_broker::Context<REQUESTS, ANSWERS>,
    clock: SharedClock,
    stop: Rc<Cell<bool>>,
    original: F,
) -> Result<T, Cause>
where
    F: Future<Output = Result<T, Cause>> + 'static,
    T: fmt::Debug + 'static,
{
    // The wrapper admitted to PROGRAM never owns the product future. Its
    // cancellation releases only its Rc; this external slot remains until the
    // same product future returns after original fixed-hard retirement.
    let state = Rc::new(RefCell::new(Original {
        future: Box::pin(original),
        result: None,
    }));
    let task = state.clone();
    let admission = Rc::new(RefCell::new(None));
    let admitted = admission.clone();
    let program = prepared
        .run_scheduled(context, clock, 1, move |_main, scope| {
            if let Err(error) = scope.spawn(poll_fn(move |cx| {
                let mut current = task.borrow_mut();
                match current.future.as_mut().poll(cx) {
                    Poll::Ready(result) => {
                        current.result = Some(result);
                        Poll::Ready(())
                    }
                    Poll::Pending => Poll::Pending,
                }
            })) {
                *admitted.borrow_mut() = Some(program::Failure::State(error));
            }
        })
        .await;
    let program = match program {
        Ok(1) => None,
        Ok(code) => Some(Box::new(std::io::Error::other(format!(
            "PROGRAM returned non-invocation code {code}"
        ))) as Cause),
        Err(error) => Some(Box::new(error) as Cause),
    };
    stop.set(true);
    if state.borrow().result.is_none() {
        // No new source, deadline, time sample or future is constructed. The
        // original failure latch makes the same foreground stop before new
        // work and settle its actual Pool under its existing native hard.
        let result = poll_fn(|cx| state.borrow_mut().future.as_mut().poll(cx)).await;
        state.borrow_mut().result = Some(result);
    }
    let result = state.borrow_mut().result.take().ok_or_else(|| {
        Box::new(std::io::Error::other(
            "original foreground future has no terminal result",
        )) as Cause
    })?;
    let admission = admission.borrow_mut().take();
    if program.is_none() && admission.is_none() {
        return result;
    }
    let (completion, task) = match result {
        Ok(value) => (Some(value), None),
        Err(error) => (None, Some(error)),
    };
    Err(Box::new(Failure {
        program,
        admission,
        task,
        completion,
    }))
}
