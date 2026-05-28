# Security Policy

## Scope

`opa-governance-library` is an advisory policy library: its policies emit `deny`
decisions, and callers enforce them. This security policy covers defects **in
this repository's policies and tooling**. It does not cover the systems that
adopt these patterns — securing a caller's enforcement layer is the adopter's
responsibility (see [`docs/threat-model.md`](docs/threat-model.md)).

## What counts as a security issue

A defect is security-relevant when a policy reaches the wrong decision in a way
that could weaken an adopter's security boundary. Examples:

- A fail-secure sentinel guard that **fails open** — a missing or malformed
  input that produces an empty `deny` set instead of a denial.
- A rule that **passes a manifest, ledger, or report it should deny**, or
  whose `severity` is too low for the defect to be acted on.
- A meta-validation rule that does not detect a missing or empty configuration
  document, so the policy silently evaluates against no thresholds.

A wrong result with no security consequence is an ordinary correctness bug —
please file it as a normal issue instead.

## Reporting

Report security issues privately through
[GitHub Security Advisories](https://github.com/jonathan-kellerai/opa-governance-library/security/advisories/new).
Do not open a public issue for a security-relevant defect.

Please include the policy package, the input that triggers the wrong decision,
the `opa` version, and the decision you expected versus the one observed.

## Supported versions

This project follows [Semantic Versioning](https://semver.org/). Security
fixes are applied to the latest released minor version.
