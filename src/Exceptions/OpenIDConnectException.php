<?php

namespace Oidc\Exceptions;

class OpenIDConnectException extends \RuntimeException {

	public function __construct(
		string $message = '',
		private readonly ?string $state = null,
		?\Throwable $previous = null,
	) {
		parent::__construct($message, previous: $previous);
	}

	/**
	 * The authorization flow's `state` this failure happened within, when one was available -
	 * null for a failure with no flow to correlate with (building a redirect before one exists,
	 * or a UserInfo/client-credentials call, neither of which goes through the state store).
	 */
	public function getState(): ?string {
		return $this->state;
	}

}
