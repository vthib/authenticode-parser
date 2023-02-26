# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.1] - 2023-02-26

### Fixed

- Fix compilation on big-endian archs.
- Fix compilation on archs where the C type `char` is unsigned.

## [0.3.0] - 2023-02-01

### Added

- Added MSRV for rust 1.60

### Changed

- Updated dependency to the authenticode-parser C library to be up to date.
- the length in `ap_authenticode_new` in `authenticode-parser-sys` is now a `i32`.

## [0.2.3] - 2023-01-08

### Fixed

- Prefixed all C exported symbols by `ap_`. This is useful to prevent linkage issues when
  other libraries also include the authenticode-parser library, but without the type fixes
  used in this version.

## [0.2.2] - 2023-01-08

### Fixed

- Prevent being able to construct a `InitializationToken` without calling the new function.

## [0.2.1] - 2023-01-08

### Added

- Added `OPENSSL_DIR` and `OPENSSL_INCLUDE_DIR` env var handling (ff5ef254).
- CI on windows and 32-bits targets (f8472ca911).

### Fixed

- Fixed the crate with 32-bits targets (0a0778b543).

## [0.2.0] - 2023-01-08

### Added

- Implement `Copy` and `Clone` traits on the `InitializationToken` struct.

## [0.1.0] - 2023-01-07

Initial release

[unreleased]: https://github.com/vthib/authenticode-parser/compare/v0.3.1...HEAD
[0.3.1]: https://github.com/vthib/authenticode-parser/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/vthib/authenticode-parser/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/vthib/authenticode-parser/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/vthib/authenticode-parser/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/vthib/authenticode-parser/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/vthib/authenticode-parser/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vthib/authenticode-parser/releases/tag/v0.0.1
