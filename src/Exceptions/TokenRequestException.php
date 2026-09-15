<?php

namespace Oidc\Exceptions;

use Oidc\ProviderError;

/**
 * Thrown when a token, introspection, revocation, or dynamic client
 * registration request fails or returns an unusable response.
 */
class TokenRequestException extends OpenIDConnectException implements ProviderErrorAwareInterface {

	public function __construct(
		string $message,
		private readonly ?int $httpStatus = null,
		private readonly ?string $rawBody = null,
		?string $state = null,
		?\Throwable $previous = null,
		private readonly ?ProviderError $providerError = null,
	) {
		parent::__construct($message, $state, $previous);
	}

	/**
	 * The response's HTTP status, when a response was actually received -
	 * null for a transport failure that never reached the server.
	 */
	public function getHttpStatus(): ?int {
		return $this->httpStatus;
	}

	/**
	 * The response's raw body, when a response was actually received -
	 * null for a transport failure that never reached the server.
	 */
	public function getRawBody(): ?string {
		return $this->rawBody;
	}

	/**
	 * The token endpoint's `error`/`error_description`/`error_uri`, when the response was a
	 * decodable JSON error body - null for a transport failure, a non-200 response with no
	 * usable JSON, or any other case where no such triple was ever available to attach.
	 */
	public function getProviderError(): ?ProviderError {
		return $this->providerError;
	}

}
