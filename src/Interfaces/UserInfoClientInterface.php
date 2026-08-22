<?php

namespace Henderjon\Oidc\Interfaces;

use Henderjon\Oidc\Claims;
use Henderjon\Oidc\Exceptions\ProviderDiscoveryException;
use Henderjon\Oidc\Exceptions\UserInfoRequestException;
use Henderjon\Oidc\OpenIDConnectClientConfig;

/**
 * Extends AuthorizationFlowClientInterface rather than standing alone,
 * because nothing fetches userinfo without also having done the
 * authorization flow first - every real caller needs both together
 * (Clever, Google, Azure AD). A caller can type-hint just this one
 * interface instead of an intersection type; an integration that never
 * fetches userinfo (e.g. LTI) can keep type-hinting the narrower
 * AuthorizationFlowClientInterface on its own.
 */
interface UserInfoClientInterface extends AuthorizationFlowClientInterface {

	/**
	 * @throws ProviderDiscoveryException
	 * @throws UserInfoRequestException
	 */
	public function fetchUserInfo( OpenIDConnectClientConfig $config, string $accessToken ): Claims;

}
