//! Actual PROGRAM/clock/shared Resolver owner, against runner-owned Unix peers.
#[cfg(feature = "resolver-broker")]
mod actual {
    use gnunet_program_host::{
        getopt::Options,
        logging::Logger,
        program::{self, Defaults, Environment, Failure, Invocation, NlsDisabled, Preparation},
        shared_clock::SharedClock,
    };
    use gnunet_resolver_broker::{
        Driver, Family, FamilyProfile, Limits, LiveConfiguration, Progress, Query, Reply,
    };
    use std::{
        cell::RefCell,
        future::{Future, poll_fn},
        io::{self, Write},
        rc::Rc,
        sync::Arc,
        task::Poll,
    };
    use tokio::time::Instant;
    fn line(value: &str) -> io::Result<()> {
        let mut out = io::stdout().lock();
        writeln!(out, "{value}")?;
        out.flush()
    }
    fn point(tag: &str, clock: &SharedClock) -> Result<(), Failure> {
        let before = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_micros();
        let logical = clock.sample()?.now.as_micros();
        let after = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_micros();
        line(&format!(
            "{tag} WALL {before} {after} LOGICAL {logical} OFFSET {}",
            clock.offset()?
        ))?;
        Ok(())
    }
    async fn query(
        mut driver: Driver<8, 1024>,
        mut query: Query<8, 1024>,
        clock: SharedClock,
    ) -> Result<(), Failure> {
        let budget = Instant::now() + std::time::Duration::from_secs(2);
        loop {
            let mut wait = Box::pin(query.next());
            let mut drive = Box::pin(driver.drive_waiting(Some(budget), |_| {}));
            let next = poll_fn(|cx| {
                if let Poll::Ready(value) = wait.as_mut().poll(cx) {
                    return Poll::Ready(value.map(Some));
                }
                match drive.as_mut().poll(cx) {
                    Poll::Ready(Ok(Progress::WaitDeadline)) => {
                        Poll::Ready(Err(gnunet_types::Error::Deadline.into()))
                    }
                    Poll::Ready(Ok(_)) => Poll::Ready(Ok(None)),
                    Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await
            .map_err(Failure::Broker)?;
            drop(wait);
            drop(drive);
            if let Some(delivery) = next {
                let delivery = delivery.ok_or(gnunet_types::Error::Closed)?;
                match delivery.reply()? {
                    Reply::Address(std::net::IpAddr::V4(address)) => {
                        let b = address.octets();
                        line(&format!(
                            "ADDRESS {:02x}{:02x}{:02x}{:02x}",
                            b[0], b[1], b[2], b[3]
                        ))?;
                    }
                    Reply::Complete(_) => {
                        point("END", &clock)?;
                        drop(delivery);
                        return Ok(());
                    }
                    _ => return Err(gnunet_types::Error::Malformed.into()),
                }
            }
        }
    }
    pub fn run() -> Result<(), Failure> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let entered = rt.enter();
        let clock = SharedClock::native(3)?;
        let mut initial = gnunet_config::Configuration::create(
            Arc::new(gnunet_config::ProjectData::default()),
            Default::default(),
        )?;
        let initial_path = std::env::var_os("OWNED_BROKER_INITIAL")
            .ok_or_else(|| io::Error::other("owned initial configuration missing"))?;
        initial.parse(std::path::Path::new(&initial_path))?;
        let (mut context, driver) = gnunet_resolver_broker::broker::<8, 1024>(
            LiveConfiguration::new(initial),
            Limits {
                io_chunk_bytes: 1,
                ..Default::default()
            },
            FamilyProfile::new(libc::AF_INET, libc::AF_INET6)?,
            Arc::new(clock.clone()),
        )
        .map_err(Failure::Broker)?;
        let config = gnunet_config::Configuration::create(
            Arc::new(gnunet_config::ProjectData::default()),
            Default::default(),
        )?;
        let mut logger = Logger::new(b"old", std::process::id(), true)?;
        let ready = program::prepare(
            config,
            Invocation {
                binary_name: b"owned-program",
                help: Some(b"Owned shared PROGRAM"),
                select_default_filename: false,
                defaults: Defaults::Native,
            },
            Options::new(),
            std::env::args_os(),
            &Environment::capture(),
            &mut NlsDisabled,
            &mut logger,
            &clock,
            &mut io::stdout(),
            &mut io::stderr(),
        )?;
        let request_context = context.clone();
        let result_slot = Rc::new(RefCell::new(None));
        let returned = Rc::clone(&result_slot);
        let clock_callback = clock.clone();
        let result = match ready {
            Preparation::Stopped(stopped) => stopped.code,
            Preparation::Ready(ready) => {
                rt.block_on(
                    ready.run_scheduled(&mut context, clock, 1, move |_, scope| {
                        let admitted = (|| -> Result<_, Failure> {
                            point("MAIN", &clock_callback)?;
                            let query = request_context
                                .ip_get(
                                    b"owned.program.invalid",
                                    Family::Any,
                                    gnunet_types::Duration(500_000),
                                )
                                .map_err(Failure::Broker)?;
                            point("QUEUED", &clock_callback)?;
                            Ok(query)
                        })();
                        match admitted {
                            Ok(query_handle) => {
                                let error_slot = Rc::clone(&returned);
                                if let Err(error) = scope.spawn(async move {
                                    *error_slot.borrow_mut() =
                                        Some(query(driver, query_handle, clock_callback).await);
                                }) {
                                    *returned.borrow_mut() = Some(Err(error.into()));
                                }
                            }
                            Err(error) => {
                                *returned.borrow_mut() = Some(Err(error));
                            }
                        }
                    }),
                )?
            }
        };
        let ended = match result_slot.borrow_mut().take() {
            Some(Ok(())) => 1,
            Some(Err(error)) => return Err(error),
            None => 0,
        };
        line(&format!(
            "RETURN {result} TASKS {} ENDS {ended}",
            u8::from(ended == 1)
        ))?;
        drop(entered);
        Ok(())
    }
}
#[cfg(feature = "resolver-broker")]
fn main() -> Result<(), gnunet_program_host::program::Failure> {
    actual::run()
}
#[cfg(not(feature = "resolver-broker"))]
fn main() -> std::io::Result<()> {
    Err(std::io::Error::other("requires resolver-broker"))
}
