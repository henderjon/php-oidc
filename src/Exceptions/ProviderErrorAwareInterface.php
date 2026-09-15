<?php

namespace Oidc\Exceptions;

use Oidc\ProviderError;

/**
 * Implemented by an exception that can carry the `error`/`error_description`/`error_uri` a
 * provider handed back, when it handed one back at all. getProviderError() returns null for a
 * transport failure, a response with no decodable error, or any other case where the
 * exception exists but no such triple was ever available to attach - not just when the
 * exception type happens to never carry one, which is why this is an interface a subset of
 * exceptions implements rather than a method on the shared OpenIDConnectException base.
 */
interface ProviderErrorAwareInterface {

	public function getProviderError(): ?ProviderError;

}
