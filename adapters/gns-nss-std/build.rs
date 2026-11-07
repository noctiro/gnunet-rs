//! GNU ELF SONAME for the actual NSS loader artifact; no install or runtime IO.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux")
        && std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu")
    {
        println!("cargo:rustc-link-arg-cdylib=-Wl,-soname,libnss_gns.so.2");
    }
}
