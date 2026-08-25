# AGENTS.md

## Project Overview

php-oidc is a small, dependency-light OpenID Connect client for PHP 8.1+. See the README's "reason" section: it
exists because most OIDC libraries over-build the spec and end up with clumsy APIs. Keep that in mind before adding
a feature - solve the common case well rather than chasing full spec coverage. This is library code consumed by
other applications, not an application itself. A change here affects every consumer, so keep the public API small,
generic, and stable. Breaking changes are allowed but must be deliberate and noted, never accidental.

## Commands

```sh
composer install                        # install dependencies
make phpunit                            # run the full test suite (vendor/bin/phpunit)
make phpstan                            # run static analysis (level 8, config in phpstan.neon)
make test                               # both of the above
vendor/bin/phpunit --filter TestClassName   # run one test class
composer update -W vendor/package       # update one dependency with its own dependents
php example/app.php                     # run the example application (see example/README.md)
```

CI (`.github/workflows/ci.yml`) runs `composer audit --locked`, `vendor/bin/phpunit`, and
`vendor/bin/phpstan analyse` against PHP 8.1 through 8.5. PHPStan is configured at level 8 over `src` only.
`test/` and `example/` are deliberately out of scope for now - add them back to `paths` in `phpstan.neon` when
they are ready. There is no configured code-style linter in this repository - do not assume `phpcs` exists.
`.editorconfig` covers whitespace only: PHP indents with tabs, everything else with spaces (2 for YAML and
Markdown, 4 otherwise).

- **Always scope dependency updates.** Use `composer update -W <vendor>/<package>` for a specific package plus its
  dependents. Never run an unbounded `composer update` - it can pull in breaking changes across the whole tree.
- **Dependency update policy.** Dependabot opens monthly update PRs for both Composer packages and GitHub Actions
  (`.github/dependabot.yml`) - review and merge those promptly rather than letting `composer.lock` drift.
  `composer audit --locked` runs in CI on every push and PR, so a runtime dependency with a known advisory fails
  the build instead of passing unnoticed; review the advisory and update the affected package (scoped, per the
  rule above) before merging past a failure there.

## Architecture

`OpenIDConnectClient` is the engine behind every capability interface (`AuthorizationFlowClientInterface`,
`TokenGrantClientInterface`, `UserInfoClientInterface`). It never talks to curl, JWKS, or a cache directly - it
composes a handful of small, independently-testable collaborators instead:

- `AuthorizationStateStore` - persists state/nonce/PKCE verifier for one in-flight attempt via an injected PSR-16
  cache.
- `ProviderMetadataResolver` - resolves one endpoint at a time, from config overrides or `.well-known` discovery.
- `IdTokenVerifier` / `ClaimsValidator` - signature verification and claims checks (issuer, audience, nonce).
- `TokenEndpointClient` / `ClientAuthenticator` - talks to `token_endpoint`, applies RFC 6749 §2.3.1 client auth.
- `Pkce` - RFC 7636 verifier/challenge generation.
- `RefreshTokenClient` - redeems a refresh token (OpenID Connect Core 1.0 §12). Implements its
  own `RefreshTokenClientInterface`, standing apart from `AuthorizationFlowClientInterface`
  since a refresh call has no state/nonce/flow in play. `OpenIDConnectClient` implements that
  interface too via a one-line delegation, so a caller holding one client object gets `refresh()`
  without reaching for a second one.

`OpenIDConnectClientFactory` is the only place that calls `new` on these collaborators and wires them together.
Construct `OpenIDConnectClient` directly only from the factory or from test code. When a new capability needs a new
collaborator, add a small class and wire it through the factory - do not grow `OpenIDConnectClient` with private
methods that belong to a concern of their own (crypto, encoding, parsing).

This composition-over-inheritance design is deliberate: other OIDC libraries (e.g. jumbojett) extend via protected
subclass hooks. This library replaces that with plain constructor injection - callers substitute a collaborator
(a fake cache, a fake HTTP fetcher) instead of subclassing anything.

## Code Style

- **Class design.** Small and single-purpose. Prefer composition over inheritance. Avoid traits, especially ones
  with state.
- **Mark classes `final` by default.** This repository's own convention differs from some sibling projects here:
  every class is `final` unless it is a deliberate extension point for a consuming application - the `Exceptions/`
  hierarchy (so callers can catch narrower or broader types), `MockOpenIDConnectClient` (a test double a consumer
  may want to customize), and `OpenIDConnectClientFactory` (wiring a consumer may want to override). Adding a new
  class that isn't one of those should be `final`.
- **Immutability.** Every value object (`FlowState`, `TokenResult`, `Claims`, `AuthenticationResult`,
  `IncomingAuthorizationResponse`, `OpenIDConnectClientConfig`, ...) is built from `readonly` properties. There are
  no mutable DTOs in this codebase - unlike some sibling projects, there is no carve-out for a "just a data bag"
  exception. `OpenIDConnectClientConfig` uses the cloning `with*()` pattern for every settable property - each
  constructor argument must have a matching `with<Property>()` method that returns a new instance. A property
  without one is a bug, not an oversight to leave for later.
- **Fail closed on anything security-relevant.** State, nonce, audience, and PKCE checks must throw
  `AuthenticationFailedException` when the expected value is missing or ambiguous, never silently skip the check.
  A missing value because "it should always be there" is exactly the case that must still be verified.
- **Typing.** Type every parameter and return, using native PHP types first and PHPDoc (`@param`, `@return`,
  array-shape syntax) only where types fall short or where an argument's shape needs documenting. Prefer `iterable`
  over `array` for arguments when either works.
- **Exceptions.**
  - Never throw a built-in PHP exception directly. Throw or extend an `Oidc\Exceptions\*` type.
  - Every exception extends `OpenIDConnectException` (itself a `\RuntimeException`), so all exceptions here are
    unchecked by convention - but still document `@throws` on any method that can throw one, so a caller can see
    the failure modes without reading the implementation.
  - Wrap exceptions from external calls (curl, JSON decoding, the HTTP fetcher) into a package exception; do not
    let a raw transport or parsing exception escape a public method.
  - Exception messages: no trailing punctuation, and never assume they are safe to show an end user as-is.
- **Docblocks explain why, not what.** Every file in `src/` opens with a docblock giving the rationale for the
  class existing and the design tradeoff it makes (see `AuthorizationStateStore`'s "replaces jumbojett's ...
  subclass hook" for the pattern). A docblock that only restates the class name in sentence form is not useful -
  delete it or replace it with the actual reasoning.
- **Writing style.** Terse, Hemingway-style. Short sentences. No contractions, no jargon. Spell out an acronym on
  first use.

## Testing

- One test file per class, named `<ClassName>Test.php`, mirroring the `src/` structure 1:1. When a class gains a
  new public method or constructor parameter, its own test file gets new test methods - do not rely on an
  end-to-end test elsewhere to stand in for unit coverage of the class actually changed.
- This repository does not use PHPUnit data providers; each behavior gets its own `test<Description>(): void`
  method, matching every existing test file. Do not introduce a data-provider-driven test here just because it is
  a common pattern elsewhere - match what is already in `test/`.
- Aim for full coverage of every branch a change introduces, including enum/mode decision matrices (e.g. every
  `PkceMode` case) and every `with*()` wither, not just the happy path. An exemption is reasonable only for a
  branch that is truly unreachable or purely defensive.
- Prefer real objects over mocks. Use the fakes already in `test/Fakes/` (`FakeHttpFetcher`, `InMemoryCache`,
  `RsaKeyFixture`, `FixedClock`) instead of adding new mocking infrastructure.
- When a value is defined by a spec (PKCE's S256 challenge, JWT claims), assert against a known test vector from
  that spec where one exists, not only against the library's own encoding of the same input.

## Documentation

- `docs/index.html` is the rendered public API reference (served via GitHub Pages from `dev`). Keep it in sync with
  any change to the public API in the same change, not a follow-up: a new class, interface, method, constructor
  parameter, `with*()` wither, enum case, or exception type all need a matching update there.
- It documents the public surface only. Internal collaborators (`AuthorizationStateStore`,
  `ProviderMetadataResolver`, `IdTokenVerifier`, `ClaimsValidator`, `TokenEndpointClient`, and similar) are
  deliberately excluded - see the page's own footer for the reasoning.

## Git

- Default branch is `dev`. Treat it as the merge target for pull requests, not a branch to commit to directly.
- Keep commits focused. A commit that adds a feature and a commit that hardens/tests it are both fine as separate
  commits; do not squash a branch down to one commit by default.
