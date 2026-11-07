use gnunet_resolver_service_core::owner::Scratch;
pub fn cannot_connect(scratch: &mut Scratch<'_>) {
    scratch.connect();
}
