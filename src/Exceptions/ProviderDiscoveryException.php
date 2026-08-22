<?php

namespace Oidc\Exceptions;

/**
 * Thrown when a provider's `.well-known/openid-configuration` or JWKS
 * document cannot be fetched, parsed, or is missing a required endpoint.
 */
class ProviderDiscoveryException extends OpenIDConnectException {

}
