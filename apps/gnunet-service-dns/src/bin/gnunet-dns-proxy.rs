//! macOS DNS system-extension executable.
#![forbid(unsafe_code)]
fn main() -> std::process::ExitCode {
    use std::io::Write;
    let mut arguments = std::env::args_os().skip(1);
    let first = arguments.next();
    if arguments.next().is_none() {
        let text = match first.as_deref().and_then(|value| value.to_str()) {
            Some("--help" | "-h") => Some("gnunet-dns-proxy runs as a macOS DNS system extension. Configure GNUNET_CONFIG through NEDNSProxyManager; use gnunet-service-dns for an ordinary service.\n".to_owned()),
            Some("--version") => Some(format!("gnunet-dns-proxy {}\n",env!("CARGO_PKG_VERSION"))),
            _ => None,
        };
        if let Some(text) = text {
            return if std::io::stdout().lock().write_all(text.as_bytes()).is_ok() {
                std::process::ExitCode::SUCCESS
            } else {
                std::process::ExitCode::FAILURE
            };
        }
    }
    gnunet_service_dns::run_provider()
}
