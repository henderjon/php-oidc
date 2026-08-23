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
	public function __construct( array $response, LoggerInterface $logger = new NullLogger ) {
		$invalidFields = [];

		if( !isset($response[self::ACCESS_TOKEN]) || !is_string($response[self::ACCESS_TOKEN]) || $response[self::ACCESS_TOKEN] === '' ) {
			$invalidFields[] = self::ACCESS_TOKEN;
		}

		foreach( [ self::TOKEN_TYPE, self::EXPIRES_IN, self::REFRESH_TOKEN, self::ID_TOKEN, self::SCOPE ] as $field ) {
			if( array_key_exists($field, $response) && $response[$field] !== null && !self::isExpectedType($field, $response[$field]) ) {
				$invalidFields[] = $field;
			}
		}

		if( $invalidFields !== [] ) {
			$logger->error('OIDC: token endpoint returned a malformed token response', [ 'invalid_fields' => $invalidFields ]);
		}

		if( in_array(self::ACCESS_TOKEN, $invalidFields, true) ) {
			throw new TokenRequestException('Token response is missing access_token');
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
		};
	}

}
