//! The ordinary production Factory uses one actual native DHT client/reader.
use crate::{Context, Factory, Failure};
use gnunet_regex_server_host::dht::{Native, NativeLimits};
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
        let limits = NativeLimits {
            operations: context.settings.driver.operations,
            bytes: context.settings.core.retained_bytes,
            query_bytes: context
                .settings
                .core
                .input_bytes
                .checked_add(1)
                .ok_or(gnunet_types::Error::Overflow)?,
            block_bytes: context.settings.core.block_bytes,
            paths: context.settings.core.output_paths,
            output_lifetime: context.settings.host.output_lifetime,
            partial_input: context.settings.host.partial_input,
            io_slice_bytes: context.settings.host.io_slice_bytes,
        };
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
