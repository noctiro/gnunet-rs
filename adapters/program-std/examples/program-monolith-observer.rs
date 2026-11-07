//! Actual bound listener and shared Resolver selection behind the monolith port.
#[cfg(all(
    feature = "runtime",
    feature = "resolver-broker",
    feature = "service-runtime"
))]
mod actual {
    use gnunet_config::Configuration;
    use gnunet_program_host::{
        daemon::{self, LoggingDiagnostics, Registry, ServiceMain},
        logging::{Logger, Stamp},
        program::{Defaults, Environment, Failure},
        runtime::Scope,
        shared_clock::SharedClock,
    };
    use gnunet_resolver_broker::{Context, FamilyProfile, Limits, LiveConfiguration};
    use gnunet_service_runtime::{Activation, BoundListeners};
    use std::{
        cell::{Cell, RefCell},
        future::poll_fn,
        io::{self, Write},
        os::unix::fs::FileTypeExt,
        path::PathBuf,
        rc::Rc,
        sync::Arc,
        task::{Poll, Waker},
    };
    fn hex(bytes: &[u8]) -> String {
        let d = b"0123456789abcdef";
        let mut s = String::new();
        for b in bytes {
            s.push(char::from(d[usize::from(b >> 4)]));
            s.push(char::from(d[usize::from(b & 15)]));
        }
        s
    }
    fn line(value: &str) -> io::Result<()> {
        let mut output = io::stdout().lock();
        writeln!(output, "{value}")?;
        output.flush()
    }
    fn live(path: &std::path::Path) -> bool {
        std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_socket())
    }
    struct Stop {
        value: Cell<bool>,
        waker: RefCell<Option<Waker>>,
    }
    impl Stop {
        fn stop(&self) {
            self.value.set(true);
            if let Some(w) = self.waker.borrow_mut().take() {
                w.wake();
            }
        }
    }
    struct ActualService {
        listeners: Option<BoundListeners>,
        context: Context<8, 1024>,
        stop: Rc<Stop>,
        initialized: Rc<Cell<u32>>,
        path: PathBuf,
        failure: Rc<RefCell<Option<io::Error>>>,
    }
    impl ServiceMain for ActualService {
        fn register<'a>(
            &'a mut self,
            _: &'a gnunet_config::ProjectData,
            config: Option<&'a Configuration>,
            scope: &Scope<'a>,
        ) -> Result<(), Failure> {
            let config = config.ok_or(gnunet_types::Error::InvalidInput)?;
            self.context
                .connect(config.duplicate()?)
                .map_err(Failure::Broker)?;
            let listeners = self.listeners.take().ok_or(gnunet_types::Error::Closed)?;
            let stop = Rc::clone(&self.stop);
            let initialized = Rc::clone(&self.initialized);
            let failure = Rc::clone(&self.failure);
            let path = self.path.clone();
            scope.spawn(async move {
                let _listeners = listeners;
                initialized.set(initialized.get() + 1);
                if let Err(error) = line(&format!(
                    "SERVICE_INIT {} SOCKET {}",
                    initialized.get(),
                    u8::from(live(&path))
                )) {
                    *failure.borrow_mut() = Some(error);
                }
                poll_fn(|cx| {
                    if stop.value.get() {
                        Poll::Ready(())
                    } else {
                        *stop.waker.borrow_mut() = Some(cx.waker().clone());
                        Poll::Pending
                    }
                })
                .await;
            })?;
            Ok(())
        }
    }
    pub fn run() -> Result<(), Failure> {
        let path = PathBuf::from(
            std::env::var_os("OWNED_MONOLITH_PATH")
                .ok_or_else(|| io::Error::other("owned Unix path required"))?,
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let entered = rt.enter();
        let clock = SharedClock::native(2)?;
        let mut logger = Logger::new(b"owned-monolith", std::process::id(), true)?;
        logger.setup_routed(
            b"owned-monolith",
            Some(b"NONE"),
            None,
            &Environment::capture().logging,
            &Stamp::setup_now()?,
            &mut io::stderr(),
        )?;
        let failure = Rc::new(RefCell::new(None));
        let errors = Rc::clone(&failure);
        let token = logger.logger_add(move |record| {
            if let Err(error) = line(&format!(
                "R {} {} {} {}",
                record.kind.0,
                hex(record.component),
                hex(record.date),
                hex(record.message)
            )) {
                *errors.borrow_mut() = Some(error);
            }
        })?;
        let mut config = Configuration::default();
        config.set_value(
            b"owned-service",
            b"UNIXPATH",
            Some(path.as_os_str().as_encoded_bytes()),
        )?;
        config.set_value(b"owned-service", b"PORT", Some(b"0"))?;
        config.set_value(b"owned-service", b"BINDTO", Some(b"127.0.0.1"))?;
        let (context, driver) = gnunet_resolver_broker::broker::<8, 1024>(
            LiveConfiguration::new(Configuration::default()),
            Limits::default(),
            FamilyProfile::new(libc::AF_INET, libc::AF_INET6)?,
            Arc::new(clock.clone()),
        )
        .map_err(Failure::Broker)?;
        let mut registry = Registry::new(2);
        let callbacks = Rc::new(Cell::new(0));
        let initialized = Rc::new(Cell::new(0));
        let stop = Rc::new(Stop {
            value: Cell::new(false),
            waker: RefCell::new(None),
        });
        for name in ["first", "newest"] {
            let count = Rc::clone(&callbacks);
            let stop = Rc::clone(&stop);
            let socket = path.clone();
            let error = Rc::clone(&failure);
            let mut diagnostics = LoggingDiagnostics {
                logger: &mut logger,
                clock: &clock,
                stderr: &mut io::stderr(),
            };
            line(&format!(
                "REGISTER {}",
                registry.register_logged(
                    name.as_bytes(),
                    b"unused",
                    move |view| {
                        count.set(count.get() + 1);
                        if let Err(e) = line(&format!(
                            "TASK {name} CFG {} SOCKET {}",
                            u8::from(view.config.is_some()),
                            u8::from(live(&socket))
                        )) {
                            *error.borrow_mut() = Some(e);
                        }
                        if name == "first" {
                            stop.stop();
                        }
                    },
                    &mut diagnostics
                )?
            ))?;
        }
        let prepared = daemon::prepare_monolith(
            Arc::new(gnunet_config::ProjectData::default()),
            Some(config),
            {
                let mut args = std::env::args_os().collect::<Vec<_>>();
                if let Some(first) = args.first_mut() {
                    *first = "owned-monolith".into();
                }
                args
            },
            Defaults::Native,
            &Environment::capture(),
            &mut logger,
            &clock,
            &mut io::stdout(),
            &mut io::stderr(),
        )?;
        if let daemon::Preparation::Ready(ready) = prepared {
            let configuration = ready
                .callback_config()
                .ok_or(gnunet_types::Error::InvalidInput)?;
            // Explicit real service-owner preparation after successful option/config
            // handling. Fresh owned path binds synchronously within this async call; no
            // input callback has run and no unrelated file creator/thread exists here.
            let listeners = rt
                .block_on(BoundListeners::bind(
                    configuration,
                    b"owned-service",
                    Activation::default(),
                ))
                .map_err(|error| io::Error::other(error.to_string()))?;
            if listeners.listeners().len() != 1 || !listeners.failures().is_empty() {
                return Err(io::Error::other("actual service listener not unique").into());
            }
            let mut service = ActualService {
                listeners: Some(listeners),
                context,
                stop,
                initialized: Rc::clone(&initialized),
                path: path.clone(),
                failure: Rc::clone(&failure),
            };
            let mut diagnostics = LoggingDiagnostics {
                logger: &mut logger,
                clock: &clock,
                stderr: &mut io::stderr(),
            };
            rt.block_on(ready.run_monolith_logged(
                &gnunet_config::ProjectData::default(),
                &mut service,
                &mut registry,
                clock.clone(),
                3,
                &mut diagnostics,
            ))?;
        }
        line(&format!(
            "DONE INIT {} TASKS {} SOCKET {}",
            initialized.get(),
            callbacks.get(),
            u8::from(live(&path))
        ))?;
        logger.logger_remove(token)?;
        if let Some(error) = failure.borrow_mut().take() {
            return Err(error.into());
        }
        drop(driver);
        drop(entered);
        Ok(())
    }
}
#[cfg(all(
    feature = "runtime",
    feature = "resolver-broker",
    feature = "service-runtime"
))]
fn main() -> Result<(), gnunet_program_host::program::Failure> {
    actual::run()
}
#[cfg(not(all(
    feature = "runtime",
    feature = "resolver-broker",
    feature = "service-runtime"
)))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::other(
        "requires actual runtime/resolver/service-runtime features",
    ))
}
