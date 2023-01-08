# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
