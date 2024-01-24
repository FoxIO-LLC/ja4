# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- ja4x: Provide more context in the error message (#52).

## [0.16.2] - 2024-01-04

### Fixed

- JA4: Include SNI (0000) and ALPN (0010) in the "original" outputs (#40).
- JA4H: Search for "Cookie" and "Referer" fields in a case-insensitive fashion.
- JA4: Take signature algorithm hex values from `signature_algorithms` extension only (#41).

## [0.16.1] - 2023-12-22

### Fixed

- JA4SSH: When counting ACK packets, look for bare ACK flags only, skipping SYN-ACK,
  PSH-ACK, FIN-ACK, etc. (#36)

## [0.16.0] - 2023-12-12

### Changed

- Handle non-ASCII ALPN strings (#16).

### Fixed

- Support tshark v4.2.0.

## [0.15.2] - 2023-11-09

### Fixed

- Ignore extraneous TCP flags when choosing packets for JA4L calculation (#22).

## [0.15.1] - 2023-10-12

### Fixed

- Don't skip X.509 certificates contained in "Server Hello" TLS packets.

## [0.15.0] - 2023-10-08

### Added

- Add capture files and expected output.

## [0.14.0] - 2023-10-04

### Added

- Add Rust sources of `ja4` and `ja4x` CLI tools.

[unreleased]: https://github.com/FoxIO-LLC/ja4/compare/v0.16.2...HEAD
[0.16.2]: https://github.com/FoxIO-LLC/ja4/compare/v0.16.1...v0.16.2
[0.16.1]: https://github.com/FoxIO-LLC/ja4/compare/v0.16.0...v0.16.1
[0.16.0]: https://github.com/FoxIO-LLC/ja4/compare/v0.15.2...v0.16.0
[0.15.2]: https://github.com/FoxIO-LLC/ja4/compare/v0.15.1...v0.15.2
[0.15.1]: https://github.com/FoxIO-LLC/ja4/compare/v0.15.0...v0.15.1
[0.15.0]: https://github.com/FoxIO-LLC/ja4/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/FoxIO-LLC/ja4/releases/tag/v0.14.0
