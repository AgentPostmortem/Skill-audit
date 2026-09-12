# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/) and semantic versioning.

## [0.1.7] - 2026-09-12

### Added

- **SKILL-SUP-003**: flag code that fetches scripts or packages over plaintext `http://`.

## [0.1.6] - 2026-09-11

### Fixed

- Reject multiple positional paths with exit code 2 instead of silently scanning only the last target.

## [0.1.5] - 2026-09-11

### Fixed

- Detect `doas` and `run0` privilege escalation alongside `sudo` in SKILL-SH-003,
  preserving its medium severity and code-only scope.

## [0.1.4] - 2026-09-09

### Fixed

- Include `.bat`, `.cmd`, `.fish`, and `.psm1` scripts in directory scans,
  including nested files and uppercase extensions.

## [0.1.3] - 2026-09-08

### Fixed

- Reject unknown CLI options with an actionable error and exit code 2 instead of silently ignoring them.

## [0.1.2] - 2026-08-23

### Fixed

- Scan extensionless scripts that begin with a shebang while continuing to
  ignore plain extensionless files.

## [0.1.1] - 2026-08-06

### Changed

- Repository moved to the `AgentPostmortem` GitHub organization; package metadata
  (`repository`, `bugs`, `homepage`) now points at the new location. The package
  name and scope are unchanged.

## [0.1.0] - 2026-07-30

### Added
- Initial release.
