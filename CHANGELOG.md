# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking changes (targeting v2.0.0)

Everything in this section is merged into `dev` but not yet released. A 1.x bug fix must branch
off the `v1.6.0` tag, not `dev` - see `AGENTS.md`'s Git section for why.

- **Removed** `OpenIDConnectClientConfig::$providerUrl`, `withProviderUrl()`, and
  `resolveIssuer()`. `issuer` is the only identifier now - it was the only one OpenID Connect
  Discovery ever defined. `providerUrl` was a holdover from this library's jumbojett-derived
  origins with no real caller depending on it being distinct from `issuer`.
- **Renamed** `OpenIDConnectClientConfig::$redirectUrl`/`withRedirectUrl()` to
  `$redirectUri`/`withRedirectUri()`, matching the spec's own `redirect_uri`.
- **Changed** `LogLevelFilterLogger`'s constructor: `bool $allow = true` is now
  `LogLevelFilterMode $mode = LogLevelFilterMode::AllowList` (new enum, cases
  `AllowList`/`DenyList`) - `allow: false` said nothing about what `false` meant without
  opening the class docblock first.

### Fixed

- `Truncate::to()` no longer splits a multi-byte UTF-8 character mid-codepoint, which could
  corrupt `json_encode()` for the whole log record it appeared in.
- Fixed `compliance/`, the RP-conformance test harness, which the `providerUrl`/`redirectUri`
  changes above had left unable to construct a config at all.
- Four latent type errors in `compliance/`, surfaced by extending PHPStan to cover it for the
  first time (see Added, below).

### Added

- A test verifying every `OpenIDConnectClientConfig` `with*()` method mutates only its own
  field, catching a silently swapped constructor argument that no other test could have
  detected.
- PHPStan now covers `compliance/` - previously unchecked entirely, which is exactly how the
  `compliance/` breakage above went undetected until a manual review found it. CI also
  syntax-checks `example/`'s runnable scripts.

## [1.6.0] - 2026-09-15

### Added

- `ProviderError`, `ProviderErrorAwareInterface`, and `getProviderError()` on
  `AuthenticationFailedException`, `TokenRequestException`, and `UserInfoRequestException` - a
  provider's `error`/`error_description`/`error_uri` is now attached to the exception itself,
  not only logged. (#104)

## [1.5.0] - 2026-09-15

### Added

- Debug-level logging across the OIDC client, for external integrators debugging their own
  integration. (#97)
- `LogLevelFilterLogger`, a PSR-3 decorator that filters to specific levels. (#99)
- Logging for `RefreshTokenClient`'s two refresh-specific outcomes. (#98)

### Fixed

- `error_description`, `error_uri`, and the UserInfo endpoint's `WWW-Authenticate`-delivered
  error detail are no longer silently dropped from any error-response log path. (#102)

## [1.4.0] - 2026-09-01

### Added

- `JSON_THROW_ON_ERROR` on every `json_decode()` call. (#85)
- Logging for the generic `curl_exec()` failure, and for the userinfo-fetch failures
  `fetchUserInfo()` is the first to see. (#86, #87)

### Fixed

- Guards against a non-array JWKS `keys` value before calling `JWK::parseKeySet()`. (#90)
- Includes the relevant URL in 8 exception messages that previously omitted it, plus `jwks_uri`
  in the key-type-mismatch message and the URL in the `curl_init()` failure message.
  (#92, #94, #95)
- `OpenIDConnectClientConfig::resolveIssuer()`'s fallback order. (#93)
- One exception message ending in a bare preposition. (#91)

## [1.3.0] - 2026-08-31

### Added

- `AuthenticationFailedException` and `UserInfoRequestException` now surface the raw
  token/response that failed. (#84)

## [1.2.0] - 2026-08-31

### Added

- `getState()` on every exception this library throws. (#78)
- An actors glossary and OIDC-vs-OAuth flow-scope documentation. (#79)

### Fixed

- HTTP status is now validated first, consistently, across every HTTP-fetching class. (#76)
- Logs expected/actual `at_hash` on a mismatch. (#77)

## [1.1.1] - 2026-08-28

### Changed

- Aligned logger context shapes and check order across the HTTP-fetching classes. (#76)

### Documentation

- Documented the logger context array keys. (#75)
- Noted that `redirectUrl` would be renamed to `redirectUri` in v2 - see `[Unreleased]` above;
  that rename has now happened. (#74)

## [1.1.0] - 2026-08-27

### Fixed

- Conformance harness test flows; adds Implicit flow support. (#73)

## [1.0.1] - 2026-08-26

### Fixed

- Widened the `psr/log` constraint to accept 1.x again. (#71)
- An incorrect final claim about `OpenIDConnectClientFactory` in the docs. (#72)

## [1.0.0] - 2026-08-26

Initial stable release: stable API, RP-conformance tested, documented.

[Unreleased]: https://github.com/henderjon/php-oidc/compare/v1.6.0...dev
[1.6.0]: https://github.com/henderjon/php-oidc/compare/v1.5.0...v1.6.0
[1.5.0]: https://github.com/henderjon/php-oidc/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/henderjon/php-oidc/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/henderjon/php-oidc/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/henderjon/php-oidc/compare/v1.1.1...v1.2.0
[1.1.1]: https://github.com/henderjon/php-oidc/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/henderjon/php-oidc/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/henderjon/php-oidc/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/henderjon/php-oidc/releases/tag/v1.0.0
