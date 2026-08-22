<?php

namespace Oidc\Interfaces;

use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\Exceptions\TokenRequestException;
use Oidc\OpenIDConnectClientConfig;
use Oidc\TokenResult;

/**
 * Non-interactive token acquisition via the client credentials grant -
 * e.g. for a service-to-service integration that needs its own access
 * token without a user in the loop.
 */
interface TokenGrantClientInterface {

	/**
	 * @param list<string> $scopes
	 * @throws ProviderDiscoveryException
	 * @throws TokenRequestException
	 */
	public function requestClientCredentialsToken( OpenIDConnectClientConfig $config, array $scopes = [] ): TokenResult;

}
