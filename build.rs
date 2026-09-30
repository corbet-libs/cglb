//! Keep the development gate out of every release profile.
fn main() {
    println!("cargo:rustc-check-cfg=cfg(cglb_development)");
    // PROFILE distinguishes release even when debug assertions are enabled.
    if std::env::var("PROFILE").as_deref() == Ok("debug") {
        println!("cargo:rustc-cfg=cglb_development");
    }
}
