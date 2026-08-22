<?php

namespace Henderjon\Oidc\Exceptions;

/**
 * Thrown when a callback carries an `error` response, an invalid or expired
 * state/nonce, or an ID token that fails signature or claims validation.
 */
class AuthenticationFailedException extends OpenIDConnectException {

}
