use gnunet_program_host::program::{Prepared,ResolverConnect,Failure};
pub fn forbidden(prepared:Prepared,resolver:&mut impl ResolverConnect)->Result<(),Failure> {
    let mut escaped=None;
    prepared.run_direct(resolver,|view|escaped=Some(view.config))?;
    drop(escaped);
    Ok(())
}
