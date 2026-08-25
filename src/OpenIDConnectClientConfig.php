<?php

namespace Oidc;

/**
 * Everything needed to talk to one OpenID Connect provider for one call.
 *
 * Replaces jumbojett's nullable constructor args plus a chain of setter
 * calls with a single immutable value. The same shape covers both a
 * statically-known integration (provider URL/issuer/credentials fixed at
 * boot) and a multi-tenant one (issuer/credentials resolved per request
 * from a database row, `providerUrl`/`issuer` passed in fresh each call).
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
	 * @param ?list<string>            $allowedHosts         Hosts every resolved endpoint (override or discovered) must
	 *                                                        match, checked by UrlPolicy. Null skips the explicit-list
	 *                                                        check and falls back to a default: the host of `issuer`
	 *                                                        (or `providerUrl`, when `issuer` is not set), or every
	 *                                                        host when neither is configured or `allowAnyHost` is set.
	 *                                                        A discovery document can name an endpoint on any host it
	 *                                                        likes - this default means that, without an explicit
	 *                                                        `allowedHosts`, a discovered endpoint still has to stay on
	 *                                                        the provider's own host to be followed.
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
	 */
	public function __construct(
		public readonly string $clientId,
		public readonly string $clientSecret,
		public readonly string $redirectUrl,
		public readonly ?string $providerUrl = null,
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
	) {
	}

	public function withClientId( string $clientId ): self {
		return new self(
			$clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	public function withClientSecret( string $clientSecret ): self {
		return new self(
			$this->clientId, $clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	public function withRedirectUrl( string $redirectUrl ): self {
		return new self(
			$this->clientId, $this->clientSecret, $redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	public function withProviderUrl( ?string $providerUrl ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	public function withIssuer( ?string $issuer ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	/**
	 * @param list<string> $scopes Merged with (not replacing) the existing scopes.
	 */
	public function withScopes( array $scopes ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			array_values(array_unique([ ...$this->scopes, ...$scopes ])),
			$this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	/**
	 * @param list<string>|string|null $audience
	 */
	public function withAudience( array|string|null $audience ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	/**
	 * @param array<string,string> $endpointOverrides Merged with (not replacing) the existing overrides.
	 */
	public function withEndpointOverrides( array $endpointOverrides ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, [ ...$this->endpointOverrides, ...$endpointOverrides ], $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	/**
	 * @param array<string,string> $extraAuthParams Merged with (not replacing) the existing params.
	 */
	public function withExtraAuthParams( array $extraAuthParams ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, [ ...$this->extraAuthParams, ...$extraAuthParams ], $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	public function withPkce( PkceMode $pkce ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	public function withAllowInsecureSchemes( bool $allowInsecureSchemes ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
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
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
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
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	/**
	 * @param ?int $maxTokenLifetimeSeconds Null clears the cap (every lifetime allowed again).
	 */
	public function withMaxTokenLifetimeSeconds( ?int $maxTokenLifetimeSeconds ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	public function withAllowUntrustedAudiences( bool $allowUntrustedAudiences ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$allowUntrustedAudiences, $this->allowAnyHost,
		);
	}

	/**
	 * Has no effect while `allowedHosts` is set explicitly - see `$allowAnyHost` above.
	 */
	public function withAllowAnyHost( bool $allowAnyHost ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms, $this->maxTokenLifetimeSeconds,
			$this->allowUntrustedAudiences, $allowAnyHost,
		);
	}

}
