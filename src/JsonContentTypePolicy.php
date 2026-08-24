<?php

namespace Oidc;

/**
 * A pure predicate, not a side-effecting guard - same shape as UrlPolicy, but with no config
 * to depend on, so this stays a plain static helper (see Pkce for the same reasoning) rather
 * than an injectable instance.
 *
 * Answers whether a response's Content-Type is one this library should attempt to parse as
 * JSON, before any parsing is attempted - not merely relying on json_decode() to fail on the
 * wrong body. A missing Content-Type is treated as acceptable rather than rejected: several
 * real providers omit the header entirely on an otherwise well-formed JSON response, and the
 * body's own JSON-validity is still checked separately regardless of this predicate's answer.
 * A present-but-wrong value (text/html, an error page, ...) is rejected outright.
 */
final class JsonContentTypePolicy {

	private const ALLOWED = [ 'application/json' ];

	/**
	 * @param list<string> $additionalAllowed Extra content types acceptable for this specific
	 *                                         call site on top of `application/json` - e.g.
	 *                                         `application/jwk-set+json` for a JWKS response.
	 */
	public static function isAcceptable( ?string $contentType, array $additionalAllowed = [] ): bool {
		if( $contentType === null ) {
			return true;
		}

		$normalized = strtolower($contentType);

		foreach( [ ...self::ALLOWED, ...$additionalAllowed ] as $allowed ) {
			if( $normalized === strtolower($allowed) ) {
				return true;
			}
		}

		return false;
	}

}
