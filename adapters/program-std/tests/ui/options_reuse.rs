use gnunet_program_host::getopt::Options;
use std::ffi::OsString;
pub fn forbidden() {
    let options=Options::new();
    drop(options.run(b"owned",[OsString::from("owned")],false));
    drop(options.run(b"owned",[OsString::from("owned")],false));
}
