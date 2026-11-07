use gnunet_program_host::locale::ProcessLocale;
fn require_send<T: Send>(_: T) {}
pub fn forbidden(locale: ProcessLocale) { require_send(locale); }
