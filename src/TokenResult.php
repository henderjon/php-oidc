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
		// field actually contained alongside which fields were flagged. Safe to log those raw
		// values verbatim: a field only lands here for having the wrong shape entirely (missing,
		// empty, or not the type the field is defined to be) - never for holding a validly-typed
		// value, so nothing here can be an access/refresh/id token that just happens to be real.
		$invalidFieldValues = [];

		if( !isset($response[self::ACCESS_TOKEN]) || !is_string($response[self::ACCESS_TOKEN]) || $response[self::ACCESS_TOKEN] === '' ) {
			$invalidFieldValues[self::ACCESS_TOKEN] = $response[self::ACCESS_TOKEN] ?? null;
		}

		foreach( [ self::TOKEN_TYPE, self::EXPIRES_IN, self::REFRESH_TOKEN, self::ID_TOKEN, self::SCOPE ] as $field ) {
			if( array_key_exists($field, $response) && $response[$field] !== null && !self::isExpectedType($field, $response[$field]) ) {
				$invalidFieldValues[$field] = $response[$field];
			}
		}

		if( $invalidFieldValues !== [] ) {
			$logger->error('OIDC: token endpoint returned a malformed token response', [
				'invalid_fields'       => array_keys($invalidFieldValues),
				'invalid_field_values' => $invalidFieldValues,
				'state'                => $state,
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

	private static function isExpectedType( string $field, mixed $value ): bool {
		return match( $field ) {
			self::TOKEN_TYPE, self::REFRESH_TOKEN, self::ID_TOKEN, self::SCOPE => is_string($value),
			self::EXPIRES_IN => is_int($value),
			default => throw new \LogicException("Unexpected field $field in token response"),
		};
	}

}
