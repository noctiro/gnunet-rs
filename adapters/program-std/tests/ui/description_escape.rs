use gnunet_program_host::{getopt::Options,helpers::{self,Target}};
pub fn forbidden()->Options<'static> {
    let description=vec![b'o',b'w',b'n'];
    let mut options=Options::new();
    options.add(helpers::flag(b'o',b"owned",&description,Target::new(0)));
    options
}
