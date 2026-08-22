<?php

namespace Henderjon\Oidc;

use Henderjon\Oidc\Exceptions\TokenRequestException;

/**
 * A token endpoint response - shared by the authorization code exchange
 * and the client credentials grant.
 */
final class TokenResult {

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
	public function __construct( array $response ) {
		if( !isset($response['access_token']) || !is_string($response['access_token']) || $response['access_token'] === '' ) {
			throw new TokenRequestException('Token response is missing access_token');
		}

		$this->accessToken  = $response['access_token'];
		$this->tokenType    = is_string($response['token_type'] ?? null) ? $response['token_type'] : self::DEFAULT_TOKEN_TYPE;
		$this->expiresIn    = is_int($response['expires_in'] ?? null) ? $response['expires_in'] : null;
		$this->refreshToken = is_string($response['refresh_token'] ?? null) ? $response['refresh_token'] : null;
		$this->idToken      = is_string($response['id_token'] ?? null) ? $response['id_token'] : null;
		$this->scope        = is_string($response['scope'] ?? null) ? $response['scope'] : null;
	}

}
