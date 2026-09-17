<?php

namespace Oidc\Exceptions;

/**
 * Thrown when AuthorizationStateStore cannot persist a new authorization
 * attempt, or cannot consume one, because the underlying cache itself
 * failed or threw - distinct from a clean miss on lookup, which is a
 * normal outcome (a forged, expired, or already-consumed state, or one
 * not even shaped like a real one), not a failure.
 */
class AuthorizationStateException extends OpenIDConnectException {

}
