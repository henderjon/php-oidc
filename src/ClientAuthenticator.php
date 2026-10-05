<?php

namespace Oidc;

use Firebase\JWT\JWT;
use Oidc\Exceptions\TokenRequestException;
use Psr\Clock\ClockInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Applies one of OpenID Connect Core 1.0 §9's Client Authentication methods (see
 * ClientAuthMethod) to a token/introspection/revocation request - HTTP Basic or client
 * credentials in the body, per `$config->clientAuthMethod` - falling back to identifying the
 * client via a bare `client_id` in the body for a public client with no secret, regardless of
 * which method is configured.
 *
 * `$logger` is optional (defaulting to a no-op) rather than a constructor dependency, since this
 * class stays static and stateless - every other collaborator that logs is a value the factory
 * wires once; this one is called straight from TokenEndpointClient, which already has its own
 * logger to hand it. Logs which method it picked and how - a mismatch with what an IdP expects
 * (Basic vs. Post, or `none` for a client the provider still expects credentials from) is a
 * common integration failure, and there is otherwise no way to confirm which one actually went
 * out without inspecting the wire. `client_secret` is never logged whole, even at debug level -
 * it is a long-lived, static credential, not a one-time code or short-lived token, so repeatedly
 * logging even a partial reveal of it still accumulates real exposure over the client's entire
 * lifetime. See Redact for the same partial-reveal handling used everywhere else in this module.
 *
 * `$state` is likewise passed in rather than held (this class stays stateless), purely so its
 * debug logs carry the same correlation id as everything else TokenEndpointClient's caller
 * touches for the same flow. Null for a grant with no in-flight flow (client credentials,
 * refresh) - there is nothing to correlate with in that case, not a missing value.
 */
final class ClientAuthenticator {

	private const ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';

	// OpenID Connect Core 1.0 §9 requires a client_secret_jwt assertion to carry a `jti` that
	// "MUST only be used once". 16 random bytes is the same strength AuthorizationStateStore
	// gives `state`, so a repeat is as unlikely as a repeated state.
	private const ASSERTION_ID_BYTES = 16;

	// Long enough to survive ordinary clock disagreement with the provider, short enough that
	// a captured assertion is useless almost at once. A provider that tracks `jti` rejects a
	// replay inside this window; one that does not still sees it expire.
	private const ASSERTION_LIFETIME_SECONDS = 60;

	/**
	 * `$audience` and `$clock` matter only for `ClientAuthMethod::ClientSecretJwt`: the assertion's
	 * `aud` is the URL the request is about to be sent to (OpenID Connect Core 1.0 §9 says it
	 * SHOULD be the token endpoint's URL), and `iat`/`exp` come from the injected clock so tests
	 * need not race the wall clock.
	 *
	 * @param array<string,string|list<string>> $params
	 * @return array{0: array<string,string|list<string>>, 1: array<string,string>} [params, headers]
	 * @throws TokenRequestException
	 */
	public static function apply(
		OpenIDConnectClientConfig $config,
		array $params,
		LoggerInterface $logger = new NullLogger,
		?string $state = null,
		?string $audience = null,
		ClockInterface $clock = new CurrentClock,
	): array {
		$headers = [ 'Content-Type' => 'application/x-www-form-urlencoded' ];

		if( $config->clientSecret === '' ) {
			$params['client_id'] = $config->clientId;

			$logger->debug('OIDC: authenticating as a public client with no client secret', [ 'client_id' => $config->clientId, 'state' => $state ]);

			return [ $params, $headers ];
		}

		if( $config->clientAuthMethod === ClientAuthMethod::ClientSecretJwt ) {
			if( $audience === null ) {
				$logger->error('OIDC: no token endpoint URL to use as the audience of a client_secret_jwt assertion', [ 'client_id' => $config->clientId, 'state' => $state, 'security_relevant' => false ]);

				throw new TokenRequestException('No token endpoint URL to use as the audience of a client_secret_jwt assertion', state: $state);
			}

			$now = $clock->now()->getTimestamp();
			$jti = bin2hex(random_bytes(self::ASSERTION_ID_BYTES));

			try {
				$assertion = JWT::encode([
					'iss' => $config->clientId,
					'sub' => $config->clientId,
					'aud' => $audience,
					'jti' => $jti,
					'iat' => $now,
					'exp' => $now + self::ASSERTION_LIFETIME_SECONDS,
				], $config->clientSecret, 'HS256');
			} catch( \DomainException $e ) {
				// php-jwt refuses an HMAC key shorter than the algorithm's digest (RFC 7518 §3.2).
				// Its message names no part of the key, so it is safe to carry along.
				$logger->error('OIDC: client secret is too short to sign a client_secret_jwt assertion with HS256', [ 'client_id' => $config->clientId, 'exception' => $e, 'state' => $state, 'security_relevant' => false ]);

				throw new TokenRequestException('Client secret is too short to sign a client_secret_jwt assertion with HS256', state: $state, previous: $e);
			}

			$params['client_id']             = $config->clientId;
			$params['client_assertion_type'] = self::ASSERTION_TYPE;
			$params['client_assertion']      = $assertion;

			// The assertion itself is never logged, only its `jti`: a provider that rejects a
			// replay names that id, so it is the one value worth finding in both logs.
			$logger->debug('OIDC: authenticating with client_secret_jwt', [ 'client_id' => $config->clientId, 'jti' => $jti, 'state' => $state ]);

			return [ $params, $headers ];
		}

		if( $config->clientAuthMethod === ClientAuthMethod::Post ) {
			$params['client_id']     = $config->clientId;
			$params['client_secret'] = $config->clientSecret;

			$logger->debug('OIDC: authenticating with client_secret_post', [ 'client_id' => $config->clientId, 'state' => $state ]);

			return [ $params, $headers ];
		}

		// RFC 6749 §2.3.1 requires the client id and secret to each be percent-encoded before
		// joining with ":" and base64-encoding - plain HTTP Basic (RFC 7617) has no such step,
		// but OAuth2 adds it so a ":"/"@"/"%" inside either value cannot be mistaken for the
		// credential separator. rawurlencode(), not urlencode() - Appendix B's encoding is
		// "application/x-www-form-urlencoded" with one override, escaping space as %20 rather
		// than "+".
		$headers['Authorization'] = 'Basic ' . base64_encode(rawurlencode($config->clientId) . ':' . rawurlencode($config->clientSecret));

		$logger->debug('OIDC: authenticating with client_secret_basic', [ 'client_id' => $config->clientId, 'state' => $state ]);

		return [ $params, $headers ];
	}

}
