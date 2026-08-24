<?php

namespace Oidc;

/**
 * A pure predicate, not a side-effecting guard: answers whether a URL this
 * library is about to fetch, or send credentials to, satisfies the policy
 * on OpenIDConnectClientConfig - scheme, and an optional host allowlist.
 * Callers decide what to do with `false` (log, throw); this class only
 * decides.
 *
 * Every endpoint this library ever touches (authorization, token, JWKS,
 * userinfo, and the discovery document itself) resolves through
 * ProviderMetadataResolver, so gating there covers all of them - both an
 * `endpointOverrides` value and one returned by the provider's own
 * discovery document, from one place.
 */
final class UrlPolicy {

	public static function isAllowed( string $url, OpenIDConnectClientConfig $config ): bool {
		$parts  = parse_url($url);
		$scheme = is_array($parts) ? ($parts['scheme'] ?? null) : null;
		$host   = is_array($parts) ? ($parts['host'] ?? null) : null;

		if( !is_string($scheme) || !is_string($host) || $host === '' ) {
			return false;
		}

		$allowedSchemes = $config->allowInsecureSchemes ? [ 'http', 'https' ] : [ 'https' ];

		if( !in_array($scheme, $allowedSchemes, true) ) {
			return false;
		}

		return $config->allowedHosts === null || in_array($host, $config->allowedHosts, true);
	}

}
