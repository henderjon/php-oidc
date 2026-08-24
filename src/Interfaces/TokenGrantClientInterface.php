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
	 * @param list<string>                      $scopes
	 * @param array<string,string|list<string>> $extraParams Provider-specific extensions to
	 *                                                        the request body. A string value is
	 *                                                        sent as-is - this covers a single
	 *                                                        `audience`, but also a provider
	 *                                                        whose multi-value convention is one
	 *                                                        space-separated string in that same
	 *                                                        key (e.g. Ory Hydra's `audience`,
	 *                                                        the same convention `scope` already
	 *                                                        uses) - join it yourself before
	 *                                                        passing it in. A list value is sent
	 *                                                        as that key repeated bare
	 *                                                        (`resource=a&resource=b`), the
	 *                                                        different convention RFC 8707
	 *                                                        specifically wants for `resource`;
	 *                                                        do not assume it is what any given
	 *                                                        provider wants for `audience` too.
	 *                                                        Not for anything this library
	 *                                                        already models explicitly; those
	 *                                                        keys are always set from
	 *                                                        $config/$scopes and cannot be
	 *                                                        overridden here.
	 * @throws ProviderDiscoveryException
	 * @throws TokenRequestException
	 */
	public function requestClientCredentialsToken( OpenIDConnectClientConfig $config, array $scopes = [], array $extraParams = [] ): TokenResult;

}
