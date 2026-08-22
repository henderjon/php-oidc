<?php

namespace Henderjon\Oidc\Interfaces;

use Henderjon\Oidc\AuthenticationResult;
use Henderjon\Oidc\AuthorizationRedirect;
use Henderjon\Oidc\Exceptions\AuthenticationFailedException;
use Henderjon\Oidc\Exceptions\ProviderDiscoveryException;
use Henderjon\Oidc\IncomingAuthorizationResponse;
use Henderjon\Oidc\OpenIDConnectClientConfig;

/**
 * Interactive login: authorization code flow (Clever, Google, Azure AD)
 * and implicit flow (e.g. LTI 1.3).
 *
 * Building a redirect never emits a response itself - it returns the URL
 * and persists state/nonce as a side effect; the caller decides how to
 * redirect.
 */
interface AuthorizationFlowClientInterface {

	/**
	 * @throws ProviderDiscoveryException
	 */
	public function buildAuthorizationCodeRedirect( OpenIDConnectClientConfig $config ): AuthorizationRedirect;

	/**
	 * @throws AuthenticationFailedException
	 * @throws ProviderDiscoveryException
	 */
	public function completeAuthorizationCodeFlow( OpenIDConnectClientConfig $config, IncomingAuthorizationResponse $response ): AuthenticationResult;

	/**
	 * @throws ProviderDiscoveryException
	 */
	public function buildImplicitFlowRedirect( OpenIDConnectClientConfig $config ): AuthorizationRedirect;

	/**
	 * @throws AuthenticationFailedException
	 * @throws ProviderDiscoveryException
	 */
	public function completeImplicitFlow( OpenIDConnectClientConfig $config, IncomingAuthorizationResponse $response ): AuthenticationResult;

}
