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
- **Changed** the host allowlist to match the port as well as the host (#122). Before, an
  allowed host made every port on that host reachable, so a discovery document or
  `endpointOverrides` value could steer a request to another service on a trusted host. An
  `allowedHosts` entry with no port now permits only the default port of the request's scheme
  (443 for `https`, 80 for `http`). Write `host:port` to permit another port. The default
  `issuer` tier uses the issuer's own explicit port when it has one. To migrate, add
  `host:port` entries for any endpoint on a non-default port, or an explicit port to a
  non-default `issuer`.
- **Changed** `max_age` in `extraAuthParams` to throw the new `ConfigurationException` when an
  authorization redirect is built (#57). Before, it reached the provider but nothing checked
  `auth_time` on the way back, so it looked enforced and was not. To migrate, replace
  `extraAuthParams: ['max_age' => '300']` with `withMaxAgeSeconds(300)`, which sends it and
  checks it.

#### Upgrading from 1.x

1. Replace `providerUrl` and `withProviderUrl()` with `issuer`.
2. Rename `redirectUrl` and `withRedirectUrl()` to `redirectUri` and `withRedirectUri()`.
3. Replace `new LogLevelFilterLogger(..., allow: false)` with
   `mode: LogLevelFilterMode::DenyList`, and `allow: true` with `LogLevelFilterMode::AllowList`.
4. Add a `host:port` entry to `allowedHosts` for any endpoint on a non-default port. An entry
   with no port now permits only 443 for `https` and 80 for `http`.
5. Replace `extraAuthParams: ['max_age' => ...]` with `withMaxAgeSeconds()`.

### Fixed

- `LogLevelFilterLogger::log()` no longer fatals on psr/log 1.x. `composer.json` allowed
  `^1.0 || ^2.0 || ^3.0`, but the `string|\Stringable` type on `$message` is narrower than 1.x's
  untyped parameter, which PHP rejects. The parameter is now untyped, documented with `@param`.
  CI now runs the test suite against each psr/log major version.
- `Truncate::to()` no longer splits a multi-byte UTF-8 character mid-codepoint, which could
  corrupt `json_encode()` for the whole log record it appeared in.
- Fixed `compliance/`, the RP-conformance test harness, which the `providerUrl`/`redirectUri`
  changes above had left unable to construct a config at all.
- Four latent type errors in `compliance/`, surfaced by extending PHPStan to cover it for the
  first time (see Added, below).

### Added

- `StatelessCodeIdTokenClient`, built with `OpenIDConnectClientFactory::makeStateless()`: a
  separate bolt-on for one vendor-driven shape, a provider that starts the login itself and
  redirects with `?code=...` and no `state`. The code is redeemed at the token endpoint and the
  ID token gets the main flow's checks minus the nonce, plus a new `iat` age check
  (`ClaimsValidator::validateIssuedAtAge()`) as the only replay defense. It gives up login CSRF
  protection and PKCE, logs a warning on every completion, and rejects any other response shape.
  `completeAuthorizationCodeFlow()` is unchanged and still requires `state`, `nonce`, and PKCE.
  Not part of OpenID Connect Core: third-party initiated login (Core §4) is the standard answer.
- `OpenIDConnectClientConfig::$maxAgeSeconds` and `withMaxAgeSeconds()` (#57). When set, the
  authorization request carries `max_age`, and the ID token must carry an `auth_time` no older
  than that plus the clock-skew leeway (`ClaimsValidator::validateAuthTime()`). Sending `max_age`
  through `extraAuthParams` now throws, see Breaking changes.
  Applies to the authorization-code and implicit flows, not to a refresh. The leeway makes a very
  small value looser than it reads: `0` does not force a fresh login, so send `prompt=login` for
  that. `ClaimsValidator` now takes a clock and a leeway, and `IdTokenVerifier` exposes its
  default as `DEFAULT_LEEWAY_SECONDS` so the two share one value.
- `ClientAuthMethod::ClientSecretJwt` (#60, `client_secret_jwt` only; `private_key_jwt` stays
  open). The token request carries a short-lived HS256 `client_assertion` signed with the client
  secret instead of the secret itself. The assertion expires after 60 seconds and has a fresh
  random `jti` every time. A client secret shorter than 32 bytes throws `TokenRequestException`
  before any request is sent. `TokenEndpointClient` takes an optional clock, and
  `ClientAuthenticator::apply()` takes an optional audience and clock. Existing calls and the
  default `Basic` method are unchanged.
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
