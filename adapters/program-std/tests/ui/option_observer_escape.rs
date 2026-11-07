#![deny(warnings)]
use gnunet_program_host::getopt::{Argument,Context,Options,Output,Spec};
use gnunet_config::diagnostic::BorrowedObserver;
pub fn forbidden(){
 let mut escaped:Option<BorrowedObserver<'_>>=None;
 let mut options=Options::new();
 options.push(Spec{short:b'x',name:b"owned",argument_help:None,description:Some(b"owned"),argument:Argument::None,mandatory:false,exclusive:false},|_:Context<'_>,_:&[u8],_:Option<&[u8]>,out:&mut Output<'_>|{escaped=out.configuration_observer();1});
 drop(options.run(b"owned",[std::ffi::OsString::from("owned"),std::ffi::OsString::from("-x")],false));
 drop(escaped);
}
