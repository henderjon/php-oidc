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
