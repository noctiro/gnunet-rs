//! Positive counterpart: returning the callback lease releases the query borrow.
#![deny(warnings)]
use gnunet_resolver_broker::{BrokerError, Query};
pub async fn lease_returned(mut query: Query<2, 64>) -> Result<(), BrokerError> {
    {
        let lease = query.next().await?;
        if let Some(lease) = lease {
            let _reply = lease.reply()?;
            drop(lease);
        }
    }
    drop(query);
    Ok(())
}
