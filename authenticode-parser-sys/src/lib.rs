//! Native bindings for the
//! [authenticode parser library](https://github.com/avast/authenticode-parser) from Avast.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
