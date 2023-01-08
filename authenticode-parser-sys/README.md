# authenticode-parser-sys

[![Crates.io](https://img.shields.io/crates/v/authenticode-parser-sys.svg)](https://crates.io/crates/authenticode-parser-sys)
[![Documentation](https://docs.rs/authenticode-parser-sys/badge.svg)](https://docs.rs/authenticode-parser-sys)

Native bindings for the [authenticode parser library](https://github.com/avast/authenticode-parser) from Avast.

This library depends on Openssl. If the library is not found by default, you can either:
- define the `OPENSSL_DIR` env variable, from which the include and library dir will be computed.
- define the `OPENSSL_INCLUDE_DIR` and `OPENSSL_LIB_DIR` env variables.
