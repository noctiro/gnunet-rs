//! Actual shared Resolver broker ports. One subscription belongs to one driver;
//! no DNS request, socket or detached task is created by clock adaptation.
use crate::program::{Failure, ResolverConnect};
use gnunet_resolver_broker::Context as Broker;
impl<const R: usize, const N: usize> ResolverConnect for Broker<R, N> {
    fn connect(&mut self, configuration: gnunet_config::Configuration) -> Result<(), Failure> {
        Broker::connect(self, configuration).map_err(Failure::Broker)
    }
}
