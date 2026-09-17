<?php

namespace Oidc\Interfaces;

use Oidc\AuthenticationResult;
use Oidc\AuthorizationRedirect;
use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Exceptions\AuthorizationStateException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClientConfig;

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
	 * @throws AuthorizationStateException
	 * @throws ProviderDiscoveryException
	 */
	public function buildAuthorizationCodeRedirect( OpenIDConnectClientConfig $config ): AuthorizationRedirect;

	/**
	 * @throws AuthenticationFailedException
	 * @throws AuthorizationStateException When the cache backend throws while consuming the
	 *         callback's state - a malformed state never reaches the cache at all, so this is
	 *         reserved for the backend genuinely failing on a well-formed one.
	 * @throws ProviderDiscoveryException
	 */
	public function completeAuthorizationCodeFlow( OpenIDConnectClientConfig $config, IncomingAuthorizationResponse $response ): AuthenticationResult;

	/**
	 * @throws AuthorizationStateException
	 * @throws ProviderDiscoveryException
	 */
	public function buildImplicitFlowRedirect( OpenIDConnectClientConfig $config ): AuthorizationRedirect;

	/**
	 * @throws AuthenticationFailedException
	 * @throws AuthorizationStateException When the cache backend throws while consuming the
	 *         callback's state - a malformed state never reaches the cache at all, so this is
	 *         reserved for the backend genuinely failing on a well-formed one.
	 * @throws ProviderDiscoveryException
	 */
	public function completeImplicitFlow( OpenIDConnectClientConfig $config, IncomingAuthorizationResponse $response ): AuthenticationResult;

}
