<?php

namespace Oidc\Exceptions;

/**
 * Thrown when AuthorizationStateStore cannot persist a new authorization
 * attempt because the underlying cache write itself failed - distinct from
 * a clean miss on lookup, which is a normal outcome (a forged, expired, or
 * already-consumed state), not a failure.
 */
class AuthorizationStateException extends OpenIDConnectException {

}
