<?php

namespace Oidc;

use Oidc\Exceptions\TokenRequestException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * A token endpoint response - shared by the authorization code exchange
 * and the client credentials grant.
 */
final class TokenResult {

	private const ACCESS_TOKEN  = 'access_token';
	private const TOKEN_TYPE    = 'token_type';
	private const EXPIRES_IN    = 'expires_in';
	private const REFRESH_TOKEN = 'refresh_token';
	private const ID_TOKEN      = 'id_token';
	private const SCOPE         = 'scope';

	private const DEFAULT_TOKEN_TYPE = 'Bearer';

	private const SENSITIVE_FIELDS = [ self::ACCESS_TOKEN, self::REFRESH_TOKEN, self::ID_TOKEN ];

	public readonly string $accessToken;

	public readonly string $tokenType;

	public readonly ?int $expiresIn;

	public readonly ?string $refreshToken;

	public readonly ?string $idToken;

	public readonly ?string $scope;

	/**
	 * @param array<string,mixed> $response Decoded JSON body from a token endpoint.
	 * @throws TokenRequestException When the response has no usable `access_token`.
	 */
	public function __construct( array $response, LoggerInterface $logger = new NullLogger, ?string $state = null ) {
		// Keyed by field name rather than a plain list, so the log below can show what each
		// field actually contained alongside which fields were flagged. A field only lands here
		// for having the wrong shape entirely (missing, empty, or not the type the field is
		// defined to be) - never for holding a validly-typed value - so a scalar or null value
		// logged here can never be a real access/refresh/id token: there is nowhere to embed an
		// arbitrary-length secret inside a bool, an int, or an empty string. A container (an
		// array, say, from a provider wrapping the field in an object instead of sending a plain
		// string) is a different case - it could still hold a real token nested inside it, so
		// loggableInvalidValue() logs only its shape, never its content, for
		// access_token/refresh_token/id_token specifically when that happens.
		$invalidFieldValues = [];

		if( !isset($response[self::ACCESS_TOKEN]) || !is_string($response[self::ACCESS_TOKEN]) || $response[self::ACCESS_TOKEN] === '' ) {
			$invalidFieldValues[self::ACCESS_TOKEN] = self::loggableInvalidValue(self::ACCESS_TOKEN, $response[self::ACCESS_TOKEN] ?? null);
		}

		foreach( [ self::TOKEN_TYPE, self::EXPIRES_IN, self::REFRESH_TOKEN, self::ID_TOKEN, self::SCOPE ] as $field ) {
			if( array_key_exists($field, $response) && $response[$field] !== null && !self::isExpectedType($field, $response[$field]) ) {
				$invalidFieldValues[$field] = self::loggableInvalidValue($field, $response[$field]);
			}
		}

		if( $invalidFieldValues !== [] ) {
			$logger->error('OIDC: token endpoint returned a malformed token response', [
				'invalid_fields'       => array_keys($invalidFieldValues),
				'invalid_field_values' => $invalidFieldValues,
				'state'                => $state,
				'security_relevant' => false,
			]);
		}

		if( array_key_exists(self::ACCESS_TOKEN, $invalidFieldValues) ) {
			throw new TokenRequestException('Token response is missing access_token', state: $state);
		}

		$this->accessToken  = $response[self::ACCESS_TOKEN];
		$this->tokenType    = is_string($response[self::TOKEN_TYPE] ?? null) ? $response[self::TOKEN_TYPE] : self::DEFAULT_TOKEN_TYPE;
		$this->expiresIn    = is_int($response[self::EXPIRES_IN] ?? null) ? $response[self::EXPIRES_IN] : null;
		$this->refreshToken = is_string($response[self::REFRESH_TOKEN] ?? null) ? $response[self::REFRESH_TOKEN] : null;
		$this->idToken      = is_string($response[self::ID_TOKEN] ?? null) ? $response[self::ID_TOKEN] : null;
		$this->scope        = is_string($response[self::SCOPE] ?? null) ? $response[self::SCOPE] : null;
	}

	/**
	 * A scalar or null value is safe to log for any field, sensitive or not - see this
	 * constructor's own comment on $invalidFieldValues for why. A container is not, but only
	 * for the three fields this library treats as sensitive everywhere else: an array logged
	 * for a mismatched token_type/expires_in/scope is just a shape a caller sent by mistake,
	 * never a place a real secret could hide, so it stays useful to see in full. Same reasoning
	 * AuthorizationStateStore::consume() applies to a cached entry it cannot trust the shape of.
	 */
	private static function loggableInvalidValue( string $field, mixed $value ): mixed {
		if( is_scalar($value) || $value === null || !in_array($field, self::SENSITIVE_FIELDS, true) ) {
			return $value;
		}

		return get_debug_type($value);
	}

	private static function isExpectedType( string $field, mixed $value ): bool {
		return match( $field ) {
			self::TOKEN_TYPE, self::REFRESH_TOKEN, self::ID_TOKEN, self::SCOPE => is_string($value),
			self::EXPIRES_IN => is_int($value),
			default => throw new \LogicException("Unexpected field $field in token response"),
		};
	}

}
