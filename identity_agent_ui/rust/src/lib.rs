mod api;

// The frb_generated module is created by `flutter_rust_bridge_codegen generate`.
// During CI/CD builds, codegen runs before compilation and creates
// `src/frb_generated.rs` with the FFI glue code.
// For local development, this module may not exist — that's OK because
// the Rust crate is only compiled as part of the mobile build pipeline.
#[cfg(not(feature = "dev_skip_frb"))]
mod frb_generated;
