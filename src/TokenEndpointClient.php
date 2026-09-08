<?php

namespace Oidc;

use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\TokenRequestException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Posts to `token_endpoint` for the three grants this module supports:
 * authorization code exchange (the interactive login flows), client
 * credentials (non-interactive, see TokenGrantClientInterface), and refresh
 * token (see RefreshTokenClientInterface). All three share the same
 * request/response shape - only `grant_type` and its params differ - so
 * one collaborator handles all of them.
 */
final class TokenEndpointClient {

	/**
	 * Param keys, among the ones this class's own callers put in $params, whose values are
	 * single-use or short-lived - an authorization code, a refresh token, a PKCE verifier -
	 * safe to partially reveal at debug level via Redact so one log line can be correlated with
	 * another. `client_secret` is never one of these: request() logs $params before handing
	 * them to ClientAuthenticator::apply(), the only place that ever adds client_secret to the
	 * body, and that class's own debug logging never reveals it at all - see its docblock for
	 * why a long-lived static credential gets different treatment than these do.
	 *
	 * This is a closed, fixed list because every key in it is one this library itself puts in
	 * $params. It cannot cover a provider-specific extension key a caller passes through
	 * requestClientCredentialsToken()'s $extraParams - this library has no way to know in
	 * advance whether a given provider's extension is secret (a signed `client_assertion`) or
	 * not (`audience`, `resource`). See that method's $sensitiveExtraParamKeys for how a caller
	 * extends this list for their own provider-specific keys; nothing outside this constant is
	 * redacted unless the caller says so.
	 *
	 * @var list<string>
	 */
	private const SENSITIVE_PARAM_KEYS = [ 'code', 'refresh_token', 'code_verifier' ];

	public function __construct(
		private readonly HttpFetcherInterface $httpFetcher,
		private readonly ProviderMetadataResolver $providerMetadataResolver,
		private readonly LoggerInterface $logger = new NullLogger,
		private readonly ?string $state = null,
	) {
	}

	/**
	 * Returns a copy of this client carrying one flow's correlation id - see
	 * ClaimsValidator::withState() for why this returns a new instance instead of mutating
	 * the shared one.
	 *
	 * Takes the caller's own already-scoped ProviderMetadataResolver rather than scoping
	 * `$this->providerMetadataResolver` itself, so both this client's token_endpoint
	 * resolution and whatever else the caller resolves during the same flow (jwks_uri, for
	 * one) share one discovery fetch instead of two independently-scoped copies each
	 * fetching it themselves.
	 */
	public function withState( ?string $state, ProviderMetadataResolver $providerMetadataResolver ): self {
		return new self($this->httpFetcher, $providerMetadataResolver, $this->logger, $state);
	}

	/**
	 * @throws TokenRequestException
	 */
	public function exchangeAuthorizationCode( OpenIDConnectClientConfig $config, string $code, ?string $codeVerifier = null ): TokenResult {
		$params = [
			'grant_type'   => 'authorization_code',
			'code'         => $code,
			'redirect_uri' => $config->redirectUrl,
		];

		if( $codeVerifier !== null ) {
			$params['code_verifier'] = $codeVerifier;
		}

		return $this->request($config, $params);
	}

	/**
	 * @param list<string>                       $scopes
	 * @param array<string,string|list<string>>  $extraParams Provider-specific extensions to
	 *                                                         the request body. A string value
	 *                                                         is sent as-is - this covers a
	 *                                                         single `audience`, but also a
	 *                                                         provider whose multi-value
	 *                                                         convention is one space-separated
	 *                                                         string in that same key (e.g. Ory
	 *                                                         Hydra's `audience`, the same
	 *                                                         convention `scope` already uses) -
	 *                                                         join it yourself before passing it
	 *                                                         in. A list value is sent as that
	 *                                                         key repeated bare
	 *                                                         (`resource=a&resource=b`), which is
	 *                                                         the different convention RFC 8707
	 *                                                         specifically wants for `resource`;
	 *                                                         do not assume it is what any given
	 *                                                         provider wants for `audience` too.
	 *                                                         Merged in before `grant_type`/
	 *                                                         `scope` are set, so neither can be
	 *                                                         overridden this way, same as
	 *                                                         `OpenIDConnectClientConfig::$extraAuthParams`
	 *                                                         on the authorization request.
	 * @param list<string> $sensitiveExtraParamKeys Which keys of $extraParams, if any, hold a
	 *                                              value this library should treat the same way
	 *                                              it treats `code`/`refresh_token`/
	 *                                              `code_verifier` - partially revealed via
	 *                                              `Redact` in the request debug log below,
	 *                                              instead of logged in full. This library has
	 *                                              no way to know what a provider-specific
	 *                                              extension key means or how sensitive its
	 *                                              value is - `audience`/`resource` are
	 *                                              typically not secret at all, but a provider
	 *                                              requiring `private_key_jwt` client
	 *                                              authentication (RFC 7523), say, would need a
	 *                                              signed `client_assertion` sent this way, and
	 *                                              that value is exactly as replayable within
	 *                                              its lifetime as `client_secret` is. Naming it
	 *                                              here is the caller's call to make, not this
	 *                                              library's to guess at - nothing outside the
	 *                                              three keys above is redacted unless the
	 *                                              caller says so.
	 * @throws TokenRequestException
	 */
	public function requestClientCredentialsToken( OpenIDConnectClientConfig $config, array $scopes = [], array $extraParams = [], array $sensitiveExtraParamKeys = [] ): TokenResult {
		$this->logOverriddenReservedParams($extraParams, [ 'grant_type', 'scope' ]);

		$params = array_merge($extraParams, [ 'grant_type' => 'client_credentials' ]);

		// scope is reserved even when $scopes is empty - "no scopes requested" must not leave
		// an extraParams-supplied scope to leak through unprotected.
		unset($params['scope']);

		if( $scopes !== [] ) {
			$params['scope'] = implode(' ', $scopes);
		}

		return $this->request($config, $params, $sensitiveExtraParamKeys);
	}

	/**
	 * OpenID Connect Core 1.0 §12.1: the refresh request authenticates to the Token Endpoint
	 * the same way as any other token request - handled by request()'s existing
	 * ClientAuthenticator::apply() call, nothing specific to this grant.
	 *
	 * @throws TokenRequestException
	 */
	public function refreshToken( OpenIDConnectClientConfig $config, string $refreshToken ): TokenResult {
		return $this->request($config, [
			'grant_type'    => 'refresh_token',
			'refresh_token' => $refreshToken,
		]);
	}

	/**
	 * @param array<string,string|list<string>> $params
	 * @param list<string> $additionalSensitiveKeys See requestClientCredentialsToken()'s own
	 *                                              docblock for $sensitiveExtraParamKeys - the
	 *                                              only caller that ever passes this.
	 * @throws TokenRequestException
	 */
	private function request( OpenIDConnectClientConfig $config, array $params, array $additionalSensitiveKeys = [] ): TokenResult {
		$endpoint = $this->providerMetadataResolver->resolve($config, ProviderMetadataResolver::TOKEN_ENDPOINT);

		$this->logger->debug('OIDC: requesting a token', [
			'endpoint' => $endpoint,
			'params'   => self::redactedParams($params, $additionalSensitiveKeys),
			'state'    => $this->state,
		]);

		[ $params, $headers ] = ClientAuthenticator::apply($config, $params, $this->logger, $this->state);

		try {
			$response = $this->httpFetcher->fetch($endpoint, $this->buildRequestBody($params), $headers);
		} catch( HttpTransportException $e ) {
			$this->logger->error('OIDC: token endpoint request could not be completed', [
				'endpoint'    => $endpoint,
				'http_status' => null,
				'exception'   => $e,
				'state'       => $this->state,
				'security_relevant' => false,
			]);

			throw new TokenRequestException("Unable to reach token endpoint {$endpoint}", state: $this->state, previous: $e);
		}

		$decoded     = null;
		$decodeError = null;

		try {
			$decoded = json_decode($response->body, true, 512, JSON_THROW_ON_ERROR);
		} catch( \JsonException $e ) {
			$decodeError = $e;
		}

		if( $response->status !== 200 ) {
			$error = is_array($decoded) && is_string($decoded['error'] ?? null) ? $decoded['error'] : "HTTP {$response->status}";

			$this->logger->error('OIDC: token endpoint returned an unsuccessful response', [
				'endpoint'       => $endpoint,
				'http_status'    => $response->status,
				'provider_error' => is_array($decoded) && is_string($decoded['error'] ?? null) ? $decoded['error'] : null,
				'content_type'   => $response->contentType,
				'state'          => $this->state,
				'security_relevant' => false,
			]);

			throw new TokenRequestException("Token request to {$endpoint} failed: {$error}", $response->status, $response->body, state: $this->state);
		}

		if( !JsonContentTypePolicy::isAcceptable($response->contentType) ) {
			$this->logger->error('OIDC: token endpoint returned an unexpected content type', [
				'endpoint'     => $endpoint,
				'http_status'  => $response->status,
				'content_type' => $response->contentType,
				'state'        => $this->state,
				'security_relevant' => false,
			]);

			throw new TokenRequestException("Token endpoint {$endpoint} returned an unexpected content type", $response->status, $response->body, state: $this->state);
		}

		if( !is_array($decoded) ) {
			$this->logger->error('OIDC: token endpoint returned invalid JSON', [
				'endpoint'     => $endpoint,
				'http_status'  => $response->status,
				'content_type' => $response->contentType,
				'exception'    => $decodeError,
				'state'        => $this->state,
				'security_relevant' => false,
			]);

			throw new TokenRequestException("Token endpoint {$endpoint} returned invalid JSON", $response->status, $response->body, state: $this->state, previous: $decodeError);
		}

		$this->logger->debug('OIDC: token endpoint returned a token', [
			'endpoint'      => $endpoint,
			'access_token'  => self::redactedField($decoded, 'access_token'),
			'id_token'      => self::redactedField($decoded, 'id_token'),
			'refresh_token' => self::redactedField($decoded, 'refresh_token'),
			'expires_in'    => $decoded['expires_in'] ?? null,
			// Neither is secret - unlike the three fields above, both are logged in full. scope
			// in particular is worth seeing next to the request's own 'params.scope' (see the
			// debug log at the top of this method): a provider narrowing what was requested is
			// a common integration surprise, easy to miss without the two side by side.
			'scope'         => self::plainField($decoded, 'scope'),
			'token_type'    => self::plainField($decoded, 'token_type'),
			'state'         => $this->state,
		]);

		return new TokenResult($decoded, $this->logger, $this->state);
	}

	/**
	 * `array_merge($extraParams, [...])` always lets the second array win on a key collision -
	 * silently, with nothing distinguishing "the caller never set this" from "the caller set it
	 * and it got overridden anyway." A caller passing `scope` or `grant_type` in `$extraParams`
	 * instead of through `$scopes` (or at all) is exactly the kind of mistake this exists to
	 * surface - the request debug log a few lines down shows the final params either way, but
	 * only this line says a collision actually happened.
	 *
	 * @param array<string,mixed> $extraParams
	 * @param list<string> $reservedKeys
	 */
	private function logOverriddenReservedParams( array $extraParams, array $reservedKeys ): void {
		$overriddenKeys = array_values(array_intersect(array_keys($extraParams), $reservedKeys));

		if( $overriddenKeys === [] ) {
			return;
		}

		$this->logger->debug('OIDC: extraParams collided with a reserved param and was overridden', [
			'overridden_keys' => $overriddenKeys,
			'state'           => $this->state,
		]);
	}

	/**
	 * @param array<string,string|list<string>> $params
	 * @param list<string> $additionalSensitiveKeys Extends SENSITIVE_PARAM_KEYS for this one
	 *                                               call - see requestClientCredentialsToken()'s
	 *                                               $sensitiveExtraParamKeys for why this
	 *                                               library cannot fill this list in on its own
	 *                                               for a provider-specific extension param.
	 * @return array<string,string|list<string>>
	 */
	private static function redactedParams( array $params, array $additionalSensitiveKeys = [] ): array {
		foreach( [ ...self::SENSITIVE_PARAM_KEYS, ...$additionalSensitiveKeys ] as $key ) {
			if( isset($params[$key]) && is_string($params[$key]) ) {
				$params[$key] = Redact::partial($params[$key]);
			}
		}

		return $params;
	}

	/**
	 * @param array<string,mixed> $decoded
	 */
	private static function redactedField( array $decoded, string $key ): ?string {
		return is_string($decoded[$key] ?? null) ? Redact::partial($decoded[$key]) : null;
	}

	/**
	 * Like redactedField(), but for a field that is not sensitive at all - returned as-is
	 * rather than through Redact::partial().
	 *
	 * @param array<string,mixed> $decoded
	 */
	private static function plainField( array $decoded, string $key ): ?string {
		return is_string($decoded[$key] ?? null) ? $decoded[$key] : null;
	}

	/**
	 * `http_build_query()` cannot produce this shape on its own - it bracket-encodes an array
	 * value (`resource[0]=a&resource[1]=b`), not the bare-repeated-key form
	 * (`resource=a&resource=b`) RFC 8707 and most authorization servers expect for a
	 * multi-valued parameter like `resource`.
	 *
	 * @param array<string,string|list<string>> $params
	 */
	private function buildRequestBody( array $params ): string {
		$pairs = [];

		foreach( $params as $key => $value ) {
			foreach( (array)$value as $item ) {
				$pairs[] = urlencode($key) . '=' . urlencode($item);
			}
		}

		return implode('&', $pairs);
	}

}
