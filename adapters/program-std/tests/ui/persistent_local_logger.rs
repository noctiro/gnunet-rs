use gnunet_program_host::logging::Logger;
use gnunet_config::Configuration;
use std::{cell::RefCell,rc::Rc,sync::Arc};
pub fn forbidden(config: &mut Configuration, logger: Rc<RefCell<Logger<'static>>>) {
    drop(config.observe(Some(Arc::new(move |_| { drop(logger.borrow_mut()); }))));
}
