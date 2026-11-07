use gnunet_resolver_service_core::owner::{Buffers, Effect, EffectTicket, Resolver, Scratch};
use gnunet_types::Error;
pub fn staging<'a>(owner: &Resolver<'a>, backing: Buffers<'a>) -> Result<Scratch<'a>, Error> {
    owner.make_scratch(backing)
}
pub fn copy_output(owner: &mut Resolver<'_>, ticket: EffectTicket,
                   persistent_tx: &mut [u8]) -> Result<usize, Error> {
    let n = match owner.effect(ticket)? {
        Effect::Output(output) => output.encode(persistent_tx)?,
        _ => return Err(Error::InvalidInput),
    };
    owner.release_effect(ticket)?;
    Ok(n)
}
