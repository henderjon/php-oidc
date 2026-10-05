<?php

namespace Oidc;

/**
 * Everything needed to talk to one OpenID Connect provider for one call.
 *
 * Replaces jumbojett's nullable constructor args plus a chain of setter
 * calls with a single immutable value. The same shape covers both a
 * statically-known integration (issuer/credentials fixed at boot) and a
 * multi-tenant one (issuer/credentials resolved per request from a
 * database row, `issuer` passed in fresh each call).
 *
 * There is deliberately no TLS-verification toggle here. Every network call this library
 * makes always verifies certificates and hostnames - the one narrow, loudly-logged exception
 * for local development lives on CurlHttpFetcher's own constructor instead, decided once per
 * fetcher instance rather than as a config value that could travel anywhere this config does.
 */
final class OpenIDConnectClientConfig {

	/**
	 * @param list<string>             $scopes
	 * @param list<string>|string|null $audience             Expected `aud` value(s), when it must differ from
	 *                                                        `clientId` - a single expected audience, or several
	 *                                                        acceptable ones. Null skips the check (see
	 *                                                        ClaimsValidator::validateAudience()). By default this
	 *                                                        doubles as the complete trusted set: any `aud` value
	 *                                                        outside it is rejected too (OpenID Connect Core 1.0
	 *                                                        §3.1.3.7 step 3), unless `allowUntrustedAudiences` opts
	 *                                                        out of that half.
	 * @param array<string,string>     $endpointOverrides    Known endpoint values (e.g. `authorization_endpoint`,
	 *                                                        `jwks_uri`, `token_endpoint`) that skip discovery for that value.
	 * @param array<string,string>     $extraAuthParams      Additional parameters merged into the authorization request.
	 *                                                        Must not contain `max_age`: building a redirect throws
	 *                                                        ConfigurationException, since nothing would check `auth_time`.
	 *                                                        Use `maxAgeSeconds`.
	 * @param ?list<string>            $allowedHosts         Bare hostnames (e.g. `login.example.com`, not
	 *                                                        `https://login.example.com`) every resolved endpoint
	 *                                                        (override or discovered) must match, checked by
	 *                                                        UrlPolicy. The port is part of the match: an entry with
	 *                                                        no port (`login.example.com`) permits only the default
	 *                                                        port of the request's scheme (443 for https, 80 for
	 *                                                        http); write `login.example.com:8443` to permit another
	 *                                                        port, and list both forms to permit both. A
	 *                                                        scheme-prefixed entry is tolerated - the host and port
	 *                                                        are recovered from it - but never write one on
	 *                                                        purpose: the scheme is stripped and ignored either way,
	 *                                                        since scheme is enforced once, globally, via
	 *                                                        `allowInsecureSchemes`, never per host. Null skips the
	 *                                                        explicit-list check and falls back to a default: the
	 *                                                        host and explicit port (if any) of `issuer`, or every
	 *                                                        host when `issuer` is not configured or `allowAnyHost`
	 *                                                        is set. A discovery document can name an endpoint on
	 *                                                        any host it likes - this default means that, without an
	 *                                                        explicit `allowedHosts`, a discovered endpoint still has
	 *                                                        to stay on the provider's own host and port to be
	 *                                                        followed.
	 * @param bool                     $allowAnyHost         Opts out of the default-to-provider-host fallback above
	 *                                                        when `allowedHosts` is null, restoring "every host allowed"
	 *                                                        for a provider that legitimately splits its endpoints
	 *                                                        across multiple hosts (e.g. Google's token/JWKS/userinfo
	 *                                                        endpoints each live on a different host than its issuer).
	 *                                                        Has no effect when `allowedHosts` is set explicitly. False
	 *                                                        by default.
	 * @param list<string>             $allowedAlgorithms    ID token signing algorithms this config accepts, checked
	 *                                                        by IdTokenVerifier before any key material is touched -
	 *                                                        the token's own `alg` header never gets to pick its own
	 *                                                        verification strategy. Defaults to RS256 only; a
	 *                                                        provider that signs with something else (HS256, PS256,
	 *                                                        ES256, ...) must be allowlisted explicitly. HS*
	 *                                                        algorithms are also always rejected outright when
	 *                                                        `clientSecret` is empty, regardless of this list.
	 * @param ?int                     $maxTokenLifetimeSeconds Caps `exp - iat` (see ClaimsValidator::validateTokenLifetime()) -
	 *                                                        independent of IdTokenVerifier's clock-skew leeway, which
	 *                                                        is a different concern. Null skips the check. Deliberately
	 *                                                        opt-in: a sensible cap depends on a given provider's own
	 *                                                        typical token lifetime, which this library cannot guess
	 *                                                        safely for every integration.
	 * @param bool                     $allowUntrustedAudiences Opts out of the "no untrusted extra audiences" half of
	 *                                                        `aud` validation (see `$audience` above), keeping only
	 *                                                        the check that the client's own expected value is
	 *                                                        present. For the rare case where a provider's tokens may
	 *                                                        legitimately carry audiences this integration cannot
	 *                                                        safely enumerate up front. False by default - both
	 *                                                        checks run unless explicitly opted out of.
	 * @param ClientAuthMethod         $clientAuthMethod     Which OpenID Connect Core 1.0 §9 method
	 *                                                        `ClientAuthenticator` uses for a confidential client.
	 *                                                        Defaults to `Basic`, the spec default when no method is
	 *                                                        registered. `ClientSecretJwt` needs a `clientSecret` of at
	 *                                                        least 32 bytes. Has no effect on a public client (empty
	 *                                                        `clientSecret`) - see `ClientAuthMethod`'s own docblock.
	 * @param ?int                     $maxAgeSeconds        OpenID Connect Core 1.0 §3.1.2.1 `max_age`: the longest the
	 *                                                        End-User's last active authentication at the provider may
	 *                                                        be, in seconds. When set, it is sent on the authorization
	 *                                                        request, and the ID token must carry an `auth_time` no
	 *                                                        older than this (see ClaimsValidator::validateAuthTime(),
	 *                                                        which also allows the verifier's clock-skew leeway, so
	 *                                                        a very small value is looser than it reads - `0` does not
	 *                                                        force a fresh login on its own, use
	 *                                                        `extraAuthParams: ['prompt' => 'login']` for that). Null
	 *                                                        sends nothing and checks nothing. Applies to the
	 *                                                        authorization-code and implicit flows, not to a refresh.
	 */
	public function __construct(
		public readonly string $clientId,
		public readonly string $clientSecret,
		public readonly string $redirectUri,
		public readonly ?string $issuer = null,
		public readonly array $scopes = [],
		public readonly array|string|null $audience = null,
		public readonly array $endpointOverrides = [],
		public readonly array $extraAuthParams = [],
		public readonly PkceMode $pkce = PkceMode::Disabled,
		public readonly bool $allowInsecureSchemes = false,
		public readonly ?array $allowedHosts = null,
		public readonly array $allowedAlgorithms = [ 'RS256' ],
		public readonly ?int $maxTokenLifetimeSeconds = null,
		public readonly bool $allowUntrustedAudiences = false,
		public readonly bool $allowAnyHost = false,
		public readonly ClientAuthMethod $clientAuthMethod = ClientAuthMethod::Basic,
		public readonly ?int $maxAgeSeconds = null,
	) {
	}

	public function withClientId( string $clientId ): self {
		return new self(
			$clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	public function withClientSecret( string $clientSecret ): self {
		return new self(
			$this->clientId, $clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	public function withRedirectUri( string $redirectUri ): self {
		return new self(
			$this->clientId, $this->clientSecret, $redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	public function withIssuer( ?string $issuer ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	/**
	 * @param list<string> $scopes Merged with (not replacing) the existing scopes.
	 */
	public function withScopes( array $scopes ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			array_values(array_unique([ ...$this->scopes, ...$scopes ])),
			$this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	/**
	 * @param list<string>|string|null $audience
	 */
	public function withAudience( array|string|null $audience ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	/**
	 * @param array<string,string> $endpointOverrides Merged with (not replacing) the existing overrides.
	 */
	public function withEndpointOverrides( array $endpointOverrides ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, [ ...$this->endpointOverrides, ...$endpointOverrides ], $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	/**
	 * @param array<string,string> $extraAuthParams Merged with (not replacing) the existing params.
	 */
	public function withExtraAuthParams( array $extraAuthParams ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, [ ...$this->extraAuthParams, ...$extraAuthParams ], $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	public function withPkce( PkceMode $pkce ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	public function withAllowInsecureSchemes( bool $allowInsecureSchemes ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	/**
	 * Replaces (does not merge with) the existing allowlist - unlike withScopes() or
	 * withEndpointOverrides(), this narrows a security boundary rather than adding to a
	 * list of extras, so two calls silently unioning their hosts would be the wrong default.
	 *
	 * @param ?list<string> $allowedHosts Null clears the explicit allowlist and falls back to
	 *                                    the default described on the constructor's
	 *                                    `$allowedHosts` parameter, rather than allowing every
	 *                                    host outright.
	 */
	public function withAllowedHosts( ?array $allowedHosts ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	/**
	 * Replaces (does not merge with) the existing allowlist - same reasoning as
	 * withAllowedHosts(): this narrows a security boundary, so unioning two calls' algorithms
	 * would be the wrong default.
	 *
	 * @param list<string> $allowedAlgorithms
	 */
	public function withAllowedAlgorithms( array $allowedAlgorithms ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	/**
	 * @param ?int $maxTokenLifetimeSeconds Null clears the cap (every lifetime allowed again).
	 */
	public function withMaxTokenLifetimeSeconds( ?int $maxTokenLifetimeSeconds ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	public function withAllowUntrustedAudiences( bool $allowUntrustedAudiences ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	/**
	 * Has no effect while `allowedHosts` is set explicitly - see `$allowAnyHost` above.
	 */
	public function withAllowAnyHost( bool $allowAnyHost ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $allowAnyHost, $this->clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	public function withClientAuthMethod( ClientAuthMethod $clientAuthMethod ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $clientAuthMethod,
			$this->maxAgeSeconds,
		);
	}

	/**
	 * Null clears it: no `max_age` is sent and `auth_time` is never checked.
	 */
	public function withMaxAgeSeconds( ?int $maxAgeSeconds ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUri, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost, $this->clientAuthMethod,
			$maxAgeSeconds,
		);
	}

}
