//! The ordinary production Factory uses one actual native DHT client/reader.
use crate::{Context, Factory, Failure};
use gnunet_regex_server_host::{dht::Native, startup::dht_limits};
/// Standard actual REGEX provider policy. Storage is owned outside the borrowed
/// provider, after fresh-exec privilege/runtime/listener preparation.
pub struct NativeFactory;
impl Factory for NativeFactory {
    type Storage = gnunet_dht_client_host::Instance;
    type Provider<'a> = Native<'a>;
    fn storage() -> Result<Self::Storage, Failure> {
        Ok(gnunet_dht_client_host::Instance::new())
    }
    fn create<'a>(context: Context<'a, Self::Storage>) -> Result<Self::Provider<'a>, Failure> {
        let limits = dht_limits(
            context.settings.core,
            context.settings.host,
            context.settings.driver,
        )?;
        if !std::sync::Arc::ptr_eq(&context.endpoint.clock(), &context.clock) {
            return Err(gnunet_types::Error::InvalidInput.into());
        }
        Native::new(
            context.storage,
            context.endpoint,
            limits,
            context.startup_until,
        )
    }
    fn ready(provider: &Self::Provider<'_>) -> Result<bool, Failure> {
        Ok(provider.ready())
    }
}
