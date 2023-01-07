//! Native bindings for the
//! [authenticode parser library](https://github.com/avast/authenticode-parser) from Avast.
//!
//! For Rust bindings on top of those types, see the
//! [authenticode-parser crate](https://crates.io/cartes/authenticode-parser).

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

#[cfg(feature = "bindgen")]
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

#[cfg(not(feature = "bindgen"))]
pub mod bindings;
#[cfg(not(feature = "bindgen"))]
pub use bindings::*;
