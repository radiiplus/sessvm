# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2026-07-20

### Added

- Added explicit `one` and `many` cardinality to persistence refs.
- Added planned lookup removals to access exchange, refresh rotation, session
  revocation, family revocation, and refresh-reuse plans.
- Added coverage for ref cardinality, stale legacy refs, refresh-family cleanup,
  and expired refresh state.

### Changed

- Relicensed the project from MIT to a choice of LGPL-3.0-only or GPL-3.0-only.
- Persistence adapters must replace the current target for `one` refs and retain
  distinct targets for `many` refs.
- The bundled memory and SQLite adapters now honor ref cardinality.
- Rotated refresh-token lookups remain available as replay-detection tombstones
  until the session expires or the refresh family is revoked.
- Revoked session and refresh lookups now resolve as not found after cleanup.

### Fixed

- Removed superseded access-token lookups during access exchange and refresh
  rotation.
- Removed access, device, session, refresh-token, and refresh-family lookups when
  a session or refresh family is revoked.
- Rejected stale access, device, and refresh refs that point at a newer or
  unrelated row.
- Rejected expired refresh/session state and removed its active lookup refs.
