#![deny(warnings)]
use gnunet_program_host::logging::{Logger,Record};
pub fn forbidden()->std::io::Result<()> {
 let mut escaped=None;
 let mut logger=Logger::new(b"owned",1,true)?;
 let _id=logger.logger_add(|record:Record<'_>|{escaped=Some(record.message);})?;
 drop(logger);
 drop(escaped);
 Ok(())
}
