# php-oidc

[![CI](https://github.com/henderjon/php-oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/henderjon/php-oidc/actions/workflows/ci.yml)

## reason

Most OIDC libraries focus on implementing all of the OIDC spec. After using a few of these libraries for simple tasks I found the APIs to have been over built and clumsily at that. This is a library made for how I use OIDC most often as a simple app builder.

The most notable divergence from the library I used previously is the injectable cache mechanism. For the simplest of app, session storage works fine but for [old school] load balanced applications where something like memcache is used to share state across servers, that mechanism needs to be injectable.

## scope

This library implements only the Relying Party (RP) / client side of OIDC. It is not an OpenID Provider (OP) and does not issue or verify tokens on behalf of a resource server. Use it to authenticate users against an external OP (authorization code flow) or to fetch access tokens for calling a downstream API (client credentials flow). It does not host authentication endpoints, issue tokens to other clients, or protect a resource server's API.

## installation

Install the package with Composer:

```sh
composer require henderjon/php-oidc
```

See the [example application](example/README.md) for basic client setup, or the [API documentation](https://henderjon.github.io/php-oidc/) for the full public API reference (docs/).

See also: [packagist](https://packagist.org/packages/henderjon/php-oidc).

## provider-initiated login without a state

Some providers start the login themselves and redirect the user to your callback with `?code=...` and no `state`. You never sent an authorization request, so there is no `state`, `nonce` or PKCE verifier to check. The main client rejects this on purpose. `StatelessCodeIdTokenClient` is a separate bolt-on for exactly this one shape.

Prefer third-party initiated login ([OpenID Connect Core §4](https://openid.net/specs/openid-connect-core-1_0.html#ThirdPartyInitiatedLogin)) wherever the provider allows it: the provider sends the user to a login initiation URL and you start an ordinary flow. Use this class only when that makes the provider re-prompt for credentials.

It accepts a bare `code`, redeems it at the token endpoint, and requires an ID token in the answer. Anything else throws, including a response that carries a `state`. The ID token gets the same checks as the main flow, minus the nonce, plus one: its `iat` must be no older than the maximum you pass.

What you give up: login CSRF protection (an attacker can hand a victim a link carrying the attacker's own valid code), replay protection by nonce (only the `iat` age check limits reuse), and PKCE. Keep the window short. Every completion logs a warning.

```php
$client = (new OpenIDConnectClientFactory($fetcher, logger: $logger))->makeStateless();

$result = $client->completeStatelessCodeFlow(
	$config,
	new IncomingAuthorizationResponse($_GET),
	maxIdTokenAgeSeconds: 120,
);

$subject = $result->claims->get('sub');
```

A provider with a different shape needs its own class. This one takes no options to cover another.

