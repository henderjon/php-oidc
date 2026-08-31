<?php

namespace Oidc;

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Verifies an ID token's signature (asymmetric via JWKS, or HMAC via the
 * client secret) using `firebase/php-jwt`, and - since the token itself is
 * authentic once the signature checks out - its `at_hash` binding to an
 * access token, if both are present.
 *
 * The token's own `alg` header never gets to pick its own verification
 * strategy: `$allowedAlgorithms` (see OpenIDConnectClientConfig::$allowedAlgorithms)
 * is checked, `none` is unconditionally rejected, and HS* is rejected outright for a
 * public client (empty client secret) - all before any key material, cached or fetched,
 * is touched. This is deliberate, not redundant with firebase/php-jwt's own internal
 * `Key`-vs-header algorithm check: this class builds the `Key` object FROM the header's
 * own `alg` (there is no other source for it - every JWT verifier has to know what the
 * token claims before it can verify it), so that internal check alone would be
 * tautological here without a policy decided independently of the token first.
 *
 * `JWT::decode()` validates `exp`/`nbf`/`iat` when they are present, but does not require
 * any of them to exist at all - a token with no `exp` claim sails through with no expiry
 * check ever applied. Requiring `exp`/`iat` (and `sub`) to actually be there is
 * ClaimsValidator's job, not this class's - see ClaimsValidator::validateRequiredClaims().
 * The injected clock exists only to make `JWT::decode()`'s own timing checks deterministic
 * in tests instead of racing against `time()`.
 *
 * `$leewaySeconds` (default 300, i.e. five minutes) is an explicit, deliberate security
 * decision, not an arbitrary default: it bounds how far this verifier's clock and the
 * issuing provider's clock are allowed to disagree before `exp`/`nbf`/`iat` are treated as
 * violated. Too small a value produces spurious rejections from ordinary clock drift between
 * this host and the provider; too large a value extends how long a token can be replayed
 * past its nominal expiry. Five minutes matches common practice for this tradeoff (the same
 * default several other OIDC client libraries ship with) and can be tightened or loosened
 * per deployment via the constructor.
 *
 * Encrypted (JWE) tokens are explicitly unsupported - detected and rejected before any key
 * material is touched.
 *
 * Issuer/audience/nonce/required-claims are not this class's concern - see ClaimsValidator.
 *
 * Every failure here is a stronger signal than a mismatched `state` or
 * `nonce` - it means the token itself is malformed, unsigned by a key we
 * trust, or otherwise not what it claims to be. Each one is logged (the
 * JOSE header, which carries no secret material, or the specific mismatch)
 * before the generic AuthenticationFailedException is thrown, so that
 * signal survives even if the caller never logs the exception itself.
 */
final class IdTokenVerifier {

	// Real-world JWKS documents rotate through a handful of keys at most; JWK::parseKeySet()
	// parses every entry unconditionally regardless of which one is actually needed, so an
	// unreasonably large key set is expensive to process even once the response itself is
	// within CurlHttpFetcher's own byte cap.
	private const MAX_JWKS_KEYS = 50;

	// A real ID token's claims are a handful of standard fields plus whatever a provider
	// adds - well under this in practice. This is checked before any work (splitting,
	// decoding) is done on the token string, and applies regardless of how the token
	// arrived: the implicit flow's id_token comes from the browser via
	// IncomingAuthorizationResponse, never through CurlHttpFetcher's own byte cap at all.
	private const MAX_ID_TOKEN_LENGTH_BYTES = 16 * 1024;

	public function __construct(
		private readonly HttpFetcherInterface $httpFetcher,
		private readonly ClockInterface $clock = new CurrentClock,
		private readonly int $leewaySeconds = 300,
		private readonly LoggerInterface $logger = new NullLogger,
		private readonly ?string $state = null,
	) {
	}

	/**
	 * Returns a copy of this verifier carrying one flow's correlation id - see
	 * ClaimsValidator::withState() for why this returns a new instance instead of
	 * mutating the shared one.
	 */
	public function withState( ?string $state ): self {
		return new self($this->httpFetcher, $this->clock, $this->leewaySeconds, $this->logger, $state);
	}

	/**
	 * @param list<string> $allowedAlgorithms See OpenIDConnectClientConfig::$allowedAlgorithms.
	 * @param bool $requireAtHash OpenID Connect Core 1.0 §3.2.2.10 makes `at_hash` REQUIRED,
	 *                             not merely checked-if-present, specifically when the ID Token
	 *                             is issued from the authorization endpoint together with an
	 *                             access token (the Implicit Flow's `id_token token` response
	 *                             type, and any Hybrid Flow combination). The Authorization
	 *                             Code Flow's ID token, issued from the token endpoint, has
	 *                             `at_hash` as OPTIONAL per §3.1.3.6 even though an access
	 *                             token accompanies it there too - callers on that flow must
	 *                             leave this `false`. Has no effect when `$accessToken` is
	 *                             null; `at_hash` is never required for an ID token issued
	 *                             with no access token alongside it.
	 * @throws AuthenticationFailedException
	 * @throws ProviderDiscoveryException
	 */
	public function verify(
		string $idToken,
		string $jwksUri,
		string $clientSecret,
		array $allowedAlgorithms = [ 'RS256' ],
		?string $accessToken = null,
		bool $requireAtHash = false,
	): Claims {
		if( strlen($idToken) > self::MAX_ID_TOKEN_LENGTH_BYTES ) {
			$this->logger->error('OIDC: ID token exceeds the maximum allowed length', [
				'length' => strlen($idToken),
				'max'    => self::MAX_ID_TOKEN_LENGTH_BYTES,
				'state'  => $this->state,
			]);

			throw new AuthenticationFailedException('ID token exceeds the maximum allowed length', state: $this->state);
		}

		$header = $this->decodeHeader($idToken);

		if( isset($header['enc']) ) {
			$this->logger->error('OIDC: ID token is encrypted (JWE), which is not supported', [ 'header' => $header, 'state' => $this->state ]);

			throw new AuthenticationFailedException('Encrypted ID tokens (JWE) are not supported', state: $this->state);
		}

		$alg = $header['alg'] ?? null;

		if( !is_string($alg) || $alg === '' ) {
			$this->logger->error('OIDC: ID token is missing its alg header', [ 'header' => $header, 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token is missing its alg header', state: $this->state);
		}

		$this->assertAlgorithmAllowed($alg, $allowedAlgorithms, $clientSecret);

		$key = str_starts_with($alg, 'HS')
			? new Key($clientSecret, $alg)
			: $this->resolveAsymmetricKey($jwksUri, $alg, is_string($header['kid'] ?? null) ? $header['kid'] : null);

		$claims = $this->decodeAndVerifySignature($idToken, $key);

		$this->verifyAccessTokenHash($claims, $alg, $accessToken, $requireAtHash);

		return $claims;
	}

	/**
	 * `none` is rejected unconditionally, even if a caller's own $allowedAlgorithms
	 * mistakenly includes it - firebase/php-jwt already refuses to decode it too, but this
	 * class does not rely solely on that. HS* is rejected outright for a public client
	 * (empty $clientSecret), also regardless of $allowedAlgorithms: a confidential client's
	 * secret is presumed genuinely unknown to an attacker, but nothing stands behind an
	 * empty one, so there is no configuration where HMAC-with-no-secret is sound.
	 *
	 * @param list<string> $allowedAlgorithms
	 * @throws AuthenticationFailedException
	 */
	private function assertAlgorithmAllowed( string $alg, array $allowedAlgorithms, string $clientSecret ): void {
		if( $alg === 'none' ) {
			$this->logger->error('OIDC: ID token declares the "none" algorithm', [ 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token algorithm "none" is not allowed', state: $this->state);
		}

		if( !in_array($alg, $allowedAlgorithms, true) ) {
			$this->logger->error('OIDC: ID token algorithm is not in the configured allowlist', [
				'alg'                => $alg,
				'allowed_algorithms' => $allowedAlgorithms,
				'state'              => $this->state,
			]);

			throw new AuthenticationFailedException("ID token algorithm \"{$alg}\" is not allowed", state: $this->state);
		}

		if( str_starts_with($alg, 'HS') && $clientSecret === '' ) {
			$this->logger->error('OIDC: ID token uses an HMAC algorithm but no client secret is configured', [ 'alg' => $alg, 'state' => $this->state ]);

			throw new AuthenticationFailedException("ID token algorithm \"{$alg}\" requires a client secret", state: $this->state);
		}
	}

	/**
	 * @throws AuthenticationFailedException
	 */
	private function decodeAndVerifySignature( string $idToken, Key $key ): Claims {
		$originalTimestamp = JWT::$timestamp;
		$originalLeeway    = JWT::$leeway;

		JWT::$timestamp = $this->clock->now()->getTimestamp();
		JWT::$leeway    = $this->leewaySeconds;

		try {
			$payload = JWT::decode($idToken, $key);
		} catch( \Exception $e ) {
			// The exception stays generic - firebase/php-jwt's own message (and whatever it
			// happens to reveal about why decoding failed) lives only in the log, matching
			// every other failure in this class and in ClaimsValidator. `previous` still
			// carries the original exception for anything inspecting the chain directly.
			$this->logger->error('OIDC: ID token signature verification failed', [ 'exception' => $e, 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token verification failed', state: $this->state, previous: $e);
		} finally {
			JWT::$timestamp = $originalTimestamp;
			JWT::$leeway    = $originalLeeway;
		}

		return new Claims($payload);
	}

	/**
	 * @throws AuthenticationFailedException
	 */
	private function verifyAccessTokenHash( Claims $claims, string $alg, ?string $accessToken, bool $requireAtHash ): void {
		if( $accessToken === null ) {
			return;
		}

		$atHash = $claims->get('at_hash');

		if( $atHash === null ) {
			if( $requireAtHash ) {
				$this->logger->error('OIDC: ID token is missing the required at_hash claim for an access token issued alongside it', [ 'alg' => $alg, 'state' => $this->state ]);

				throw new AuthenticationFailedException('ID token is missing the required at_hash claim', state: $this->state);
			}

			return;
		}

		$bitLength = match( true ) {
			str_ends_with($alg, '384') => 384,
			str_ends_with($alg, '512') => 512,
			default                    => 256,
		};

		$digest   = hash('sha' . $bitLength, $accessToken, true);
		$expected = JWT::urlsafeB64Encode(substr($digest, 0, intdiv($bitLength, 16)));

		if( !hash_equals($expected, (string)$atHash) ) {
			// Safe to log both sides, unlike the access token itself: at_hash is a one-way
			// digest of it, so neither value here can be reversed back into the access token
			// that produced it.
			$this->logger->error('OIDC: ID token at_hash does not match the access token', [
				'alg'              => $alg,
				'expected_at_hash' => $expected,
				'actual_at_hash'   => (string)$atHash,
				'state'            => $this->state,
			]);

			throw new AuthenticationFailedException('ID token at_hash does not match the access token', state: $this->state);
		}
	}

	/**
	 * @throws AuthenticationFailedException
	 * @throws ProviderDiscoveryException
	 */
	private function resolveAsymmetricKey( string $jwksUri, string $alg, ?string $kid ): Key {
		$jwks = $this->fetchJwks($jwksUri);
		$this->assertKeyCountWithinLimit($jwks, $jwksUri);

		// firebase/php-jwt throws its own exception (UnexpectedValueException,
		// InvalidArgumentException, ...) for a malformed, missing, or empty "keys" member -
		// none of which is an AuthenticationFailedException. Every other malformed-input path
		// in this class becomes one of those, logged first; this call is not an exception to
		// that just because the rejection happens inside a dependency instead of this class's
		// own code.
		try {
			$keySet = JWK::parseKeySet($jwks, $alg);
		} catch( \Exception $e ) {
			$this->logger->error('OIDC: unable to parse the JWKS document', [
				'jwks_uri'  => $jwksUri,
				'exception' => $e,
				'state'     => $this->state,
			]);

			throw new AuthenticationFailedException('Unable to parse the JWKS document', state: $this->state, previous: $e);
		}

		$selectedKid = match( true ) {
			$kid !== null && isset($keySet[$kid]) => $kid,
			default                                => $this->findSoleSigningCandidate($jwks, $keySet, $alg),
		};

		if( $selectedKid === null ) {
			$this->logger->error('OIDC: unable to find a matching JWKS key for this ID token', [
				'kid'            => $kid,
				'available_kids' => array_keys($keySet),
				'state'          => $this->state,
			]);

			throw new AuthenticationFailedException('Unable to find a matching JWKS key for this ID token', state: $this->state);
		}

		$this->assertKeyTypeMatchesAlgorithm($jwks, $selectedKid, $alg);

		return $keySet[$selectedKid];
	}

	/**
	 * @param array<string,mixed> $jwks
	 * @throws AuthenticationFailedException
	 */
	private function assertKeyCountWithinLimit( array $jwks, string $jwksUri ): void {
		$keys = is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [];

		if( count($keys) <= self::MAX_JWKS_KEYS ) {
			return;
		}

		$this->logger->error('OIDC: JWKS document exceeds the maximum number of keys', [
			'jwks_uri'  => $jwksUri,
			'key_count' => count($keys),
			'max_keys'  => self::MAX_JWKS_KEYS,
			'state'     => $this->state,
		]);

		throw new AuthenticationFailedException('JWKS document exceeds the maximum number of keys', state: $this->state);
	}

	/**
	 * When `kid` is absent, narrows the candidate set to keys actually usable for verifying
	 * this specific algorithm, rather than every key `JWK::parseKeySet()` happened to parse -
	 * a JWKS commonly carries an encryption key alongside its signing key(s) (RFC 7517 §4.2's
	 * "use" is OPTIONAL, so its absence is not itself exclusionary - but an entry explicitly
	 * marked "enc" is never a signature candidate regardless), and, when a provider signs with
	 * more than one algorithm family, a signing key for each of those. `count($keySet) === 1`
	 * alone conflates all of that with genuine ambiguity: a JWKS with one RS256 signing key
	 * and one unrelated encryption key is not actually ambiguous for an RS256 token, but it
	 * has two entries.
	 *
	 * Filters the RAW JWKS entries, not the already-parsed `$keySet` - `JWK::parseKeySet()`
	 * exposes only each `Key`'s (possibly tautological, see assertKeyTypeMatchesAlgorithm())
	 * algorithm label, not the JWK's original "use"/"kty" - the same reason
	 * assertKeyTypeMatchesAlgorithm() itself reads from `$jwks` directly.
	 *
	 * @param array<string,mixed> $jwks
	 * @param array<string,Key> $keySet
	 */
	private function findSoleSigningCandidate( array $jwks, array $keySet, string $alg ): ?string {
		$expectedKty = self::expectedKtyFor($alg);
		$keys        = is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [];
		$candidates  = [];

		foreach( $keys as $index => $entry ) {
			$entryKid = is_string($entry['kid'] ?? null) ? $entry['kid'] : (string)$index;

			if( !isset($keySet[$entryKid]) ) {
				// Failed to parse (e.g. an unsupported curve) - JWK::parseKeySet() already
				// dropped it, so it was never a candidate to begin with.
				continue;
			}

			if( ( $entry['use'] ?? null ) === 'enc' ) {
				continue;
			}

			if( $expectedKty !== null && ( $entry['kty'] ?? null ) !== $expectedKty ) {
				continue;
			}

			$candidates[] = $entryKid;
		}

		return count($candidates) === 1 ? $candidates[0] : null;
	}

	/**
	 * The algorithm family a JWK's own "kty" must declare to be usable for $alg - shared by
	 * findSoleSigningCandidate() (narrowing candidates before selection) and
	 * assertKeyTypeMatchesAlgorithm() (verifying the final selection independently of
	 * firebase/php-jwt's own, otherwise tautological, internal check - see that method's own
	 * docblock).
	 */
	private static function expectedKtyFor( string $alg ): ?string {
		return match( true ) {
			str_starts_with($alg, 'RS'), str_starts_with($alg, 'PS') => 'RSA',
			str_starts_with($alg, 'ES')                              => 'EC',
			$alg === 'EdDSA'                                         => 'OKP',
			// Anything else is outside firebase/php-jwt's own supported algorithm list and
			// will already be rejected by JWT::decode() itself - nothing to check here.
			default                                                  => null,
		};
	}

	/**
	 * A JWKS entry's own "alg" is optional (RFC 7517 §4.4) - when it is absent,
	 * JWK::parseKeySet() labels the resulting Key with whatever algorithm this class asked
	 * for, which is the token's own (already allowlist-checked) `alg`. That means
	 * firebase/php-jwt's internal "does the Key's algorithm match the token header"
	 * check - the one this class's own class docblock explains is otherwise tautological
	 * here - would trivially pass even if the JWKS entry it resolved to is structurally the
	 * wrong kind of key for that algorithm (an EC key selected for an RS256 token, say).
	 * This checks the selected entry's own declared "kty" against the algorithm family
	 * independently of that internal check, using the raw JWKS document rather than the
	 * already-parsed Key objects, since a Key exposes only its (possibly tautological)
	 * algorithm label, not the JWK's original "kty".
	 *
	 * @param array<string,mixed> $jwks
	 * @throws AuthenticationFailedException
	 */
	private function assertKeyTypeMatchesAlgorithm( array $jwks, string $selectedKid, string $alg ): void {
		$expectedKty = self::expectedKtyFor($alg);

		if( $expectedKty === null ) {
			return;
		}

		// A malformed "keys" value never reaches here today - JWK::parseKeySet() above
		// already rejects every shape this cast would otherwise let through, before this
		// method is ever called. Matches assertKeyCountWithinLimit()'s own guard anyway,
		// rather than leaving this method's safety implicitly dependent on a specific
		// firebase/php-jwt version continuing to reject exactly what it does today.
		$keys = is_array($jwks['keys'] ?? null) ? $jwks['keys'] : [];

		foreach( $keys as $index => $entry ) {
			if( ( $entry['kid'] ?? (string)$index ) !== $selectedKid ) {
				continue;
			}

			$actualKty = $entry['kty'] ?? null;

			if( $actualKty !== $expectedKty ) {
				$this->logger->error('OIDC: JWKS key type does not match the ID token algorithm', [
					'alg'          => $alg,
					'expected_kty' => $expectedKty,
					'actual_kty'   => $actualKty,
					'kid'          => $selectedKid,
					'state'        => $this->state,
				]);

				throw new AuthenticationFailedException('JWKS key type does not match the ID token algorithm', state: $this->state);
			}

			return;
		}
	}

	/**
	 * @throws ProviderDiscoveryException
	 * @return array<string,mixed>
	 */
	private function fetchJwks( string $jwksUri ): array {
		try {
			$response = $this->httpFetcher->fetch($jwksUri, null);
		} catch( HttpTransportException $e ) {
			$this->logger->error('OIDC: unable to fetch JWKS', [
				'jwks_uri'     => $jwksUri,
				'http_status'  => null,
				'content_type' => null,
				'exception'    => $e,
				'state'        => $this->state,
			]);

			throw new ProviderDiscoveryException("Unable to fetch JWKS from {$jwksUri}", state: $this->state, previous: $e);
		}

		if( $response->status !== 200 ) {
			$this->logger->error('OIDC: JWKS endpoint returned an unsuccessful response', [
				'jwks_uri'     => $jwksUri,
				'http_status'  => $response->status,
				'content_type' => $response->contentType,
				'state'        => $this->state,
			]);

			throw new ProviderDiscoveryException("JWKS endpoint {$jwksUri} returned HTTP {$response->status}", state: $this->state);
		}

		if( !JsonContentTypePolicy::isAcceptable($response->contentType, [ 'application/jwk-set+json' ]) ) {
			$this->logger->error('OIDC: JWKS endpoint returned an unexpected content type', [
				'jwks_uri'     => $jwksUri,
				'http_status'  => $response->status,
				'content_type' => $response->contentType,
				'state'        => $this->state,
			]);

			throw new ProviderDiscoveryException("JWKS endpoint {$jwksUri} returned an unexpected content type", state: $this->state);
		}

		$decoded     = null;
		$decodeError = null;

		try {
			$decoded = json_decode($response->body, true, 512, JSON_THROW_ON_ERROR);
		} catch( \JsonException $e ) {
			$decodeError = $e;
		}

		if( !is_array($decoded) ) {
			$this->logger->error('OIDC: JWKS endpoint returned invalid JSON', [
				'jwks_uri'     => $jwksUri,
				'http_status'  => $response->status,
				'content_type' => $response->contentType,
				'exception'    => $decodeError,
				'state'        => $this->state,
			]);

			throw new ProviderDiscoveryException("JWKS endpoint {$jwksUri} returned invalid JSON", state: $this->state, previous: $decodeError);
		}

		return $decoded;
	}

	/**
	 * @throws AuthenticationFailedException
	 * @return array<string,mixed>
	 */
	private function decodeHeader( string $idToken ): array {
		$segments = explode('.', $idToken);

		if( count($segments) !== 3 ) {
			$this->logger->error('OIDC: ID token is not a well-formed JWT', [ 'segment_count' => count($segments), 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token is not a well-formed JWT', state: $this->state);
		}

		$decoded     = null;
		$decodeError = null;

		try {
			$decoded = json_decode(JWT::urlsafeB64Decode($segments[0]), true, 512, JSON_THROW_ON_ERROR);
		} catch( \JsonException $e ) {
			$decodeError = $e;
		}

		if( !is_array($decoded) ) {
			$this->logger->error('OIDC: ID token header is not valid JSON', [ 'exception' => $decodeError, 'state' => $this->state ]);

			throw new AuthenticationFailedException('ID token header is not valid JSON', state: $this->state, previous: $decodeError);
		}

		return $decoded;
	}

}
