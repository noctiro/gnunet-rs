#![deny(warnings)]
use gnunet_program_host::{getopt::Options,program::{Prepared,ResolverConnect,Failure},logging::Logger,config_observer,shared_clock::SharedClock};
use gnunet_config::Configuration;
use std::{cell::RefCell,ffi::OsString};
pub fn config_send_sync(){fn require<T:Send+Sync>(){}require::<Configuration>();}
pub fn owned_main(prepared:Prepared,resolver:&mut impl ResolverConnect)->Result<Option<Result<Configuration,gnunet_config::Error>>,Failure>{let mut owned=None;prepared.run_direct(resolver,|view|owned=Some(view.config.duplicate()))?;Ok(owned)}
pub fn owned_options(){let options=Options::new();let result=options.run(b"owned",[OsString::from("owned")],false);drop(result);}
pub fn local_observer(logger:&mut Logger<'_>,clock:&SharedClock,config:&mut Configuration)->std::io::Result<()> {let mut stderr=Vec::new();let copied=RefCell::new(Vec::new());let result=config_observer::operation(logger,clock,&mut stderr,|observer|config.deserialize_observed(b"broken\n",None,Some(&|event:gnunet_config::diagnostic::Diagnostic<'_>|{copied.borrow_mut().push(event.template.to_vec());observer(event);})))?;drop(result);drop(copied);Ok(())}
pub fn owned_option_run_after_observer_drop(){let run={let events=RefCell::new(Vec::new());let observer=|event:gnunet_config::diagnostic::Diagnostic<'_>|events.borrow_mut().push(event.template.to_vec());Options::new().run_translated_observed(b"owned",[OsString::from("owned")],false,gnunet_program_host::locale::disabled(),Some(&observer))};drop(run);}
