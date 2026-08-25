<?php

namespace Oidc\Interfaces;

use Oidc\Claims;
use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\Exceptions\UserInfoRequestException;
use Oidc\OpenIDConnectClientConfig;

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
	 * $expectedSubject must be the sub Claim from the authenticated ID token
	 * (AuthenticationResult::$claims->get('sub')). OpenID Connect Core 1.0 §5.3.2 requires the
	 * UserInfo response's sub to be verified against it, to guard against token substitution.
	 *
	 * @throws ProviderDiscoveryException
	 * @throws UserInfoRequestException
	 */
	public function fetchUserInfo( OpenIDConnectClientConfig $config, string $accessToken, string $expectedSubject ): Claims;

}
