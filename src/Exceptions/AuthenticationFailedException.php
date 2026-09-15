<?php

namespace Oidc\Exceptions;

use Oidc\ProviderError;

/**
 * Thrown when a callback carries an `error` response, an invalid or expired
 * state/nonce, or an ID token that fails signature or claims validation.
 */
class AuthenticationFailedException extends OpenIDConnectException implements ProviderErrorAwareInterface {

	public function __construct(
		string $message = '',
		private readonly ?string $idToken = null,
		?string $state = null,
		?\Throwable $previous = null,
		private readonly ?ProviderError $providerError = null,
	) {
		parent::__construct($message, $state, $previous);
	}

	/**
	 * The raw ID token this failure happened against, when one was actually obtained - null
	 * for a failure with no token yet in hand (a state/nonce/PKCE mismatch, a missing
	 * authorization code, a provider-returned error, or a token response with no id_token at
	 * all - that last case IS the failure, so there is nothing to attach).
	 *
	 * Attached at the boundary where the raw token is in scope (OpenIDConnectClient's
	 * authorization-code/implicit flows, RefreshTokenClient's refresh flow) rather than
	 * threaded into ClaimsValidator/IdTokenVerifier themselves - every failure either of
	 * those collaborators can throw already bubbles up through one of those two boundaries
	 * uncaught, so attaching it there once covers both without changing either collaborator's
	 * own signatures.
	 *
	 * A signature/claims failure is exactly the case where seeing every claim at once -
	 * not just the one(s) the specific check that failed happened to log - matters most:
	 * validation is fail-fast, so the log for whichever check tripped first never shows the
	 * others. Decoding this (it need not be signature-valid to decode) is the only way to see
	 * the whole picture in one place.
	 */
	public function getIdToken(): ?string {
		return $this->idToken;
	}

	/**
	 * The provider's `error`/`error_description`/`error_uri`, when this failure came from a
	 * provider-reported error on the callback - null for every other kind of failure this
	 * exception covers (state/nonce/PKCE mismatch, a missing code, ID token validation).
	 */
	public function getProviderError(): ?ProviderError {
		return $this->providerError;
	}

}
