use gnunet_resolver_service_core::owner::{Effect, EffectTicket, Resolver};
use gnunet_types::Error;
pub fn escape(owner: &mut Resolver<'_>, ticket: EffectTicket) -> Result<(), Error> {
    let view = owner.effect(ticket)?;
    owner.release_effect(ticket)?;
    if let Effect::StartQuery(query) = view { assert!(!query.bytes.is_empty()); }
    Ok(())
}
