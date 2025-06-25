# Changelog

All notable changes to this project will be documented in this file.

## [1.12.0] 
- Added automatic update checks using GitHub releases.
- New `--self-update` flag installs updates when available
- New `--no-update-check` flag disables update checks
- Updated rules

## [1.11.0] 2025-06-21
- Increased default value for number of scanning jobs to improve validation speed
- Fixed issue where some API responses (e.g. GitHub's `/user` endpoint) include required fields like `"name"` beyond the first 512 bytes. Truncating earlier causes `WordMatch` checks to fail even for active credentials. Increased the limit to keep a larger slice of the body while still bounding memory usage.

## [1.10.0] 2025-06-20
- Updated de-dupe fingerprint to include the content of the match
- Updated Makefile
- Adding GitHub Actions

## [1.9.0] 2025-06-16
- Initial public release of Kingfisher
