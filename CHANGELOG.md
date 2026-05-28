# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-05-20

Initial public release of the OPA Rego governance policy library.

### Added

- **circuit-breaker-policy** — a governance pattern for short-circuiting
  evaluation under failure or threshold conditions, with example input and
  data documents.
- **audit-trail-policy** — a governance pattern for validating and enforcing
  audit-trail requirements, with example input and data documents.
- **plugin-governance** — a governance pattern for controlling plugin
  registration and permissions.
- **Test suites** for all three pillars: 38 tests covering the
  plugin-governance pattern, plus the circuit-breaker and audit-trail test
  suites.
- **Example inputs** — representative `input.example.json` documents for each
  policy pillar to support local evaluation with `opa eval`.
- **Documentation** — repository-level guidance covering policy structure,
  usage, and contribution intake.

[0.1.0]: https://github.com/jonathan-kellerai/opa-governance-library/releases/tag/v0.1.0
