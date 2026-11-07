//! Must fail because an actual callback lease still borrows its original query.
#![deny(warnings)]
use gnunet_resolver_broker::{BrokerError, Query};
pub async fn lease_live(mut query: Query<2, 64>) -> Result<(), BrokerError> {
    let lease = query.next().await?;
    drop(query);
    if let Some(lease) = lease {
        let _reply = lease.reply()?;
    }
    Ok(())
}
