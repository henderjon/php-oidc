<?php

namespace Oidc;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * A pure predicate, not a side-effecting guard: answers whether a URL this
 * library is about to fetch, or send credentials to, satisfies the policy
 * on OpenIDConnectClientConfig - scheme, and a host-and-port check.
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
 * URL must stay on the provider's own host (`issuer`) - a discovery document
 * naming an endpoint on some other host does not get followed just because
 * no allowlist was ever set up. See defaultAllowedOrigin() for why that tier
 * falls back to unrestricted, rather than rejecting everything, when
 * `issuer` is not configured at all.
 *
 * The port is part of the match, not just the host: an allowed host does not make every
 * service on that host reachable. A URL with no explicit port has the default port of its own
 * scheme (443 for https, 80 for http). An `allowedHosts` entry is `host` or `host:port`; an
 * entry with no port permits only the default port of the request's scheme. The `issuer`
 * default tier follows the same rule, using the issuer's own explicit port when it has one.
 *
 * Each `$config->allowedHosts` entry is meant to be a bare hostname (or `host:port`), but a
 * caller pasting a full endpoint URL (scheme included, e.g. copied straight from a provider's
 * documentation) is an easy mistake to make - and, unlike a mismatched host, this one used to
 * fail every request silently: a bare hostname parsed from the real URL can never string-equal
 * a scheme-prefixed entry, so nothing would ever pass. normalizedAllowedOrigin() recovers the
 * host and port from that shape instead. This is safe to do unconditionally: the scheme on an
 * entry, if present, was never consulted for anything - the scheme of the actual request is
 * checked once, above, against `allowInsecureSchemes`, entirely independently of
 * `allowedHosts` - so stripping it here changes nothing about which schemes are actually
 * permitted.
 *
 * `$logger` does not make this a side-effecting guard after all - isAllowed()'s return value
 * is still all callers ever act on. It exists solely so normalizedAllowedOrigin() can surface,
 * at debug level, the one case worth a caller knowing about even though nothing failed: an
 * `allowedHosts` entry that was itself wrong (a full URL, not a bare hostname) and got quietly
 * corrected rather than rejected.
 */
final class UrlPolicy {

	public function __construct(
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

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

		$port = $parts['port'] ?? self::defaultPort($scheme);

		if( $config->allowedHosts !== null ) {
			foreach( $config->allowedHosts as $entry ) {
				if( $this->matches($host, $port, $scheme, $this->normalizedAllowedOrigin($entry)) ) {
					return true;
				}
			}

			return false;
		}

		if( $config->allowAnyHost ) {
			return true;
		}

		$defaultOrigin = self::defaultAllowedOrigin($config);

		return $defaultOrigin === null || $this->matches($host, $port, $scheme, $defaultOrigin);
	}

	/**
	 * @param array{host: string, port: ?int} $origin
	 */
	private function matches( string $host, int $port, string $scheme, array $origin ): bool {
		return $host === $origin['host'] && $port === ( $origin['port'] ?? self::defaultPort($scheme) );
	}

	private static function defaultPort( string $scheme ): int {
		return $scheme === 'https' ? 443 : 80;
	}

	/**
	 * Splits an `allowedHosts` entry into its host and optional port. The ordinary entry is a
	 * bare hostname, returned unchanged with no port. `host:port` yields both. See the class
	 * docblock for why a full URL is tolerated too and why that is safe: the host and port are
	 * recovered from it and the scheme is dropped.
	 *
	 * @return array{host: string, port: ?int}
	 */
	private function normalizedAllowedOrigin( string $value ): array {
		if( !str_contains($value, ':') ) {
			return [ 'host' => $value, 'port' => null ];
		}

		$isFullUrl = str_contains($value, '://');
		$parts     = parse_url($isFullUrl ? $value : '//' . $value);
		$host      = is_array($parts) ? ($parts['host'] ?? null) : null;

		if( !is_string($host) ) {
			return [ 'host' => $value, 'port' => null ];
		}

		$port = $parts['port'] ?? null;

		if( $isFullUrl ) {
			// debug, not warning like ClaimsValidator's analogous malformed-value case: dropping a
			// malformed aud entry under allowUntrustedAudiences actually loses information - the
			// resulting trusted-audience set is less complete than the caller thinks, while a
			// looser security posture is being exercised right now. Recovering a host from a
			// scheme-prefixed allowedHosts entry loses nothing and exercises no looser posture at
			// all - the effective check behaves exactly as if the entry had been written correctly
			// in the first place, purely a caller ergonomics correction.
			$this->logger->debug('OIDC: an allowedHosts entry looks like a full URL rather than a bare hostname - using the host recovered from it', [
				'configured_entry' => $value,
				'recovered_host'   => $host,
				'recovered_port'   => $port,
			]);
		}

		return [ 'host' => $host, 'port' => $port ];
	}

	/**
	 * The one origin trusted by default when the caller has set neither an explicit
	 * `allowedHosts` nor `allowAnyHost`: the host (and explicit port, if any) of the config's own `issuer` - the same value
	 * ProviderMetadataResolver already fetches discovery from and validates the discovery
	 * document's own `issuer` claim against.
	 *
	 * Returns null - meaning "no default to enforce, allow it" - when `issuer` is not
	 * configured at all. That is a deliberate choice, not an oversight: with it unset,
	 * ProviderMetadataResolver never performs discovery in the first place (see its own null
	 * check), so every URL this predicate is ever asked about in that configuration is exactly
	 * what the caller's own `endpointOverrides` declared in code - not something a discovery
	 * document could have redirected. There is no discovery-driven trust boundary to protect
	 * in that shape, so defaulting to a restriction here would only punish a caller who never
	 * uses discovery at all.
	 */
	/**
	 * @return ?array{host: string, port: ?int}
	 */
	private static function defaultAllowedOrigin( OpenIDConnectClientConfig $config ): ?array {
		$issuer = $config->issuer;

		if( $issuer === null ) {
			return null;
		}

		$parts = parse_url($issuer);
		$host  = is_array($parts) ? ($parts['host'] ?? null) : null;

		return is_string($host) ? [ 'host' => $host, 'port' => $parts['port'] ?? null ] : null;
	}

}
