<?php

namespace Oidc\Stateless;

use Oidc\AuthenticationResult;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\ConfigurationException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\Exceptions\TokenRequestException;
use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClientConfig;

/**
 * The one capability StatelessCodeIdTokenClient offers, kept apart from every interface the
 * main client implements so a consumer cannot pick it up by accident. See that class for the
 * exact response shape and what it gives up.
 */
interface StatelessCodeIdTokenClientInterface {

	/**
	 * @param int         $maxIdTokenAgeSeconds The longest ago the ID token's `iat` may be. Must be positive.
	 * @param ?string     $redirectUriOverride  Sent to the token endpoint instead of the config's `redirectUri`.
	 *
	 * @throws AuthenticationFailedException
	 * @throws ConfigurationException
	 * @throws ProviderDiscoveryException
	 * @throws TokenRequestException
	 */
	public function completeStatelessCodeFlow(
		OpenIDConnectClientConfig $config,
		IncomingAuthorizationResponse $response,
		int $maxIdTokenAgeSeconds,
		?string $redirectUriOverride = null,
	): AuthenticationResult;

}
