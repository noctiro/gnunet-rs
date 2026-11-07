use gnunet_config::{Configuration,diagnostic::Diagnostic};
pub fn forbidden(config: &mut Configuration) {
    let escaped=std::cell::RefCell::new(None);
    let observer=|event:Diagnostic<'_>|*escaped.borrow_mut()=Some(event.arguments);
    drop(config.deserialize_observed(b"broken\n",None,Some(&observer)));
    drop(escaped);
}
