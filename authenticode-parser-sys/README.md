# authenticode-parser-sys

[![Crates.io](https://img.shields.io/crates/v/authenticode-parser-sys.svg)](https://crates.io/crates/authenticode-parser-sys)
[![Documentation](https://docs.rs/authenticode-parser-sys/badge.svg)](https://docs.rs/authenticode-parser-sys)

Native bindings for the [authenticode parser library](https://github.com/avast/authenticode-parser) from Avast.

This library depends on Openssl. You might need to set the env variable `OPENSSL_LIB_DIR` to indicate where
the openssl library is located.
