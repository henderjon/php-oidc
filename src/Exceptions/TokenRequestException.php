<?php

namespace Oidc\Exceptions;

/**
 * Thrown when a token, introspection, revocation, or dynamic client
 * registration request fails or returns an unusable response.
 */
class TokenRequestException extends OpenIDConnectException {

	public function __construct(
		string $message,
		private readonly ?int $httpStatus = null,
		private readonly ?string $rawBody = null,
		?\Throwable $previous = null,
	) {
		parent::__construct($message, previous: $previous);
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

}
