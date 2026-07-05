//! Clock shim: `SystemTime` that also works on `wasm32-unknown-unknown`.
//!
//! `std::time::SystemTime::now()` panics on bare wasm; `web-time` is a
//! drop-in that reads the JS clock there and delegates to std everywhere
//! else. Every in-crate `SystemTime` use goes through this module so the
//! choice lives in one place.

#[cfg(all(target_arch = "wasm32", target_os = "unknown"))]
pub use web_time::SystemTime;

#[cfg(not(all(target_arch = "wasm32", target_os = "unknown")))]
pub use std::time::SystemTime;
