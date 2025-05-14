# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.3] - 2025-05-14

### Added
-   Introduced `bodyEncoding` option in `AuthConfig` and related functions (`getAuthToken`, `verifyAuthToken`). This allows the request `body` to be treated as `utf8` (default), `hex`, or `base64` when generating the signature.

### Changed
-   Updated test suite in `test/auth.test.ts` to reflect the new token format and to include comprehensive tests for different `bodyEncoding` options.

### Fixed
-   Removed redundant outer Base64 encoding previously applied to the entire token. The signature within the token remains Base64 encoded as per BSM or BRC-77 requirements.
-   Removed an unused `toUTF8` import from `src/auth.ts`.

---
_Please replace YYYY-MM-DD with the actual release date._ 