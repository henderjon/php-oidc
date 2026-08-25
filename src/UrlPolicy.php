<?php

namespace Oidc;

/**
 * A pure predicate, not a side-effecting guard: answers whether a URL this
 * library is about to fetch, or send credentials to, satisfies the policy
 * on OpenIDConnectClientConfig - scheme, and a host check.
 * Callers decide what to do with `false` (log, throw); this class only
 * decides.
 *
 * Every endpoint this library ever touches (authorization, token, JWKS,
 * userinfo, and the discovery document itself) resolves through
 * ProviderMetadataResolver, so gating there covers all of them - both an
 * `endpointOverrides` value and one returned by the provider's own
 * discovery document, from one place.
 *
 * The host check has three tiers, most specific first: an explicit
 * `$config->allowedHosts` always wins outright when set; `$allowAnyHost`
 * opts out of the tier below entirely; otherwise a discovered or overridden
 * URL must stay on the provider's own host (`issuer`, or `providerUrl` when
 * `issuer` is not set) - a discovery document naming an endpoint on some
 * other host does not get followed just because no allowlist was ever set
 * up. See defaultAllowedHost() for why that tier falls back to unrestricted,
 * rather than rejecting everything, when neither `issuer` nor `providerUrl`
 * is configured at all.
 *
 * Each `$config->allowedHosts` entry is meant to be a bare hostname, but a caller pasting a
 * full endpoint URL (scheme included, e.g. copied straight from a provider's documentation) is
 * an easy mistake to make - and, unlike a mismatched host, this one used to fail every request
 * silently: a bare hostname parsed from the real URL can never string-equal a scheme-prefixed
 * entry, so nothing would ever pass. normalizedAllowedHost() recovers the host from that shape
 * instead. This is safe to do unconditionally: the scheme on an entry, if present, was never
 * consulted for anything - the scheme of the actual request is checked once, above, against
 * `allowInsecureSchemes`, entirely independently of `allowedHosts` - so stripping it here
 * changes nothing about which schemes are actually permitted.
 */
final class UrlPolicy {

	public function isAllowed( string $url, OpenIDConnectClientConfig $config ): bool {
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

		if( $config->allowedHosts !== null ) {
			$allowedHosts = array_map(self::normalizedAllowedHost(...), $config->allowedHosts);

			return in_array($host, $allowedHosts, true);
		}

		if( $config->allowAnyHost ) {
			return true;
		}

		$defaultHost = self::defaultAllowedHost($config);

		return $defaultHost === null || $host === $defaultHost;
	}

	/**
	 * See the class docblock for why this exists and why it is safe: recovers the host from an
	 * `allowedHosts` entry that turned out to be a full URL instead of a bare hostname. Returns
	 * the entry unchanged when it has no scheme to strip - the ordinary, documented case.
	 */
	private static function normalizedAllowedHost( string $value ): string {
		if( !str_contains($value, '://') ) {
			return $value;
		}

		$host = parse_url($value, PHP_URL_HOST);

		return is_string($host) ? $host : $value;
	}

	/**
	 * The one host trusted by default when the caller has set neither an explicit
	 * `allowedHosts` nor `allowAnyHost`: the config's own `issuer` (or `providerUrl`, when
	 * `issuer` is not set) - the same value ProviderMetadataResolver already fetches
	 * discovery from and validates the discovery document's own `issuer` claim against.
	 *
	 * Returns null - meaning "no default to enforce, allow it" - when neither `issuer` nor
	 * `providerUrl` is configured at all. That is a deliberate choice, not an oversight: with
	 * neither set, ProviderMetadataResolver never performs discovery in the first place (see
	 * its own null check), so every URL this predicate is ever asked about in that
	 * configuration is exactly what the caller's own `endpointOverrides` declared in code -
	 * not something a discovery document could have redirected. There is no discovery-driven
	 * trust boundary to protect in that shape, so defaulting to a restriction here would only
	 * punish a caller who never uses discovery at all.
	 */
	private static function defaultAllowedHost( OpenIDConnectClientConfig $config ): ?string {
		$providerUrl = $config->issuer ?? $config->providerUrl;

		if( $providerUrl === null ) {
			return null;
		}

		$host = parse_url($providerUrl, PHP_URL_HOST);

		return is_string($host) ? $host : null;
	}

}
