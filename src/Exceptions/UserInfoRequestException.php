<?php

namespace Oidc\Exceptions;

use Oidc\ProviderError;

/**
 * Thrown when the userinfo endpoint cannot be reached or returns an
 * unusable response.
 */
class UserInfoRequestException extends OpenIDConnectException implements ProviderErrorAwareInterface {

	public function __construct(
		string $message = '',
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
	 * The response's raw body, when a response was actually received - null for a transport
	 * failure that never reached the server. For a signed (`application/jwt`) response that
	 * failed further signature or claims validation, this is the same JWT that failed -
	 * decoding it (it need not be signature-valid to decode) shows every claim it carried at
	 * once, not just whichever one the specific check that failed happened to log.
	 */
	public function getRawBody(): ?string {
		return $this->rawBody;
	}

	/**
	 * The userinfo endpoint's `error`/`error_description`/`error_uri`, parsed from the
	 * WWW-Authenticate response header per OpenID Connect Core 1.0 §5.3.3 / RFC 6750 §3 - null
	 * for a transport failure, a response with no such header, or any other failure this
	 * exception covers that carries no provider-reported error at all.
	 */
	public function getProviderError(): ?ProviderError {
		return $this->providerError;
	}

}
