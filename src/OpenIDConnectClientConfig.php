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
 */
final class OpenIDConnectClientConfig {

	/**
	 * @param list<string>             $scopes
	 * @param list<string>|string|null $audience             Expected `aud` value(s), when it must differ from
	 *                                                        `clientId` - a single expected audience, or several
	 *                                                        acceptable ones. Null skips the check (see
	 *                                                        ClaimsValidator::validateAudience()).
	 * @param array<string,string>     $endpointOverrides    Known endpoint values (e.g. `authorization_endpoint`,
	 *                                                        `jwks_uri`, `token_endpoint`) that skip discovery for that value.
	 * @param array<string,string>     $extraAuthParams      Additional parameters merged into the authorization request.
	 * @param ?list<string>            $allowedHosts         Hosts every resolved endpoint (override or discovered) must
	 *                                                        match, checked by UrlPolicy. Null skips the check. Meant for
	 *                                                        multi-tenant deployments where provider configuration is
	 *                                                        resolved per request and might be attacker- or
	 *                                                        tenant-influenced - a single, statically-known integration
	 *                                                        usually has no need for it.
	 * @param list<string>             $allowedAlgorithms    ID token signing algorithms this config accepts, checked
	 *                                                        by IdTokenVerifier before any key material is touched -
	 *                                                        the token's own `alg` header never gets to pick its own
	 *                                                        verification strategy. Defaults to RS256 only; a
	 *                                                        provider that signs with something else (HS256, PS256,
	 *                                                        ES256, ...) must be allowlisted explicitly. HS*
	 *                                                        algorithms are also always rejected outright when
	 *                                                        `clientSecret` is empty, regardless of this list.
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
		public readonly bool $verifyTls = true,
		public readonly PkceMode $pkce = PkceMode::Disabled,
		public readonly bool $allowInsecureSchemes = false,
		public readonly ?array $allowedHosts = null,
		public readonly array $allowedAlgorithms = [ 'RS256' ],
	) {
	}

	public function withClientId( string $clientId ): self {
		return new self(
			$clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	public function withClientSecret( string $clientSecret ): self {
		return new self(
			$this->clientId, $clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	public function withRedirectUrl( string $redirectUrl ): self {
		return new self(
			$this->clientId, $this->clientSecret, $redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	public function withProviderUrl( ?string $providerUrl ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	public function withIssuer( ?string $issuer ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	/**
	 * @param list<string> $scopes Merged with (not replacing) the existing scopes.
	 */
	public function withScopes( array $scopes ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			array_values(array_unique([ ...$this->scopes, ...$scopes ])),
			$this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	/**
	 * @param list<string>|string|null $audience
	 */
	public function withAudience( array|string|null $audience ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $audience, $this->endpointOverrides, $this->extraAuthParams, $this->verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	/**
	 * @param array<string,string> $endpointOverrides Merged with (not replacing) the existing overrides.
	 */
	public function withEndpointOverrides( array $endpointOverrides ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, [ ...$this->endpointOverrides, ...$endpointOverrides ], $this->extraAuthParams, $this->verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	/**
	 * @param array<string,string> $extraAuthParams Merged with (not replacing) the existing params.
	 */
	public function withExtraAuthParams( array $extraAuthParams ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, [ ...$this->extraAuthParams, ...$extraAuthParams ], $this->verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	public function withVerifyTls( bool $verifyTls ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	public function withPkce( PkceMode $pkce ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->verifyTls, $pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	public function withAllowInsecureSchemes( bool $allowInsecureSchemes ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->verifyTls, $this->pkce,
			$allowInsecureSchemes, $this->allowedHosts, $this->allowedAlgorithms,
		);
	}

	/**
	 * Replaces (does not merge with) the existing allowlist - unlike withScopes() or
	 * withEndpointOverrides(), this narrows a security boundary rather than adding to a
	 * list of extras, so two calls silently unioning their hosts would be the wrong default.
	 *
	 * @param ?list<string> $allowedHosts Null clears the allowlist (every host allowed again).
	 */
	public function withAllowedHosts( ?array $allowedHosts ): self {
		return new self(
			$this->clientId, $this->clientSecret, $this->redirectUrl, $this->providerUrl, $this->issuer,
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $allowedHosts, $this->allowedAlgorithms,
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
			$this->scopes, $this->audience, $this->endpointOverrides, $this->extraAuthParams, $this->verifyTls, $this->pkce,
			$this->allowInsecureSchemes, $this->allowedHosts, $allowedAlgorithms,
		);
	}

}
