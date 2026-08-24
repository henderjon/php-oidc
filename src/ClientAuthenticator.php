<?php

namespace Oidc;

/**
 * Applies RFC 6749 §2.3.1 client authentication to a token/introspection/
 * revocation request: HTTP Basic when a client secret is configured,
 * falling back to identifying the client via `client_id` in the body for
 * a public client with none.
 */
final class ClientAuthenticator {

	/**
	 * @param array<string,string|list<string>> $params
	 * @return array{0: array<string,string|list<string>>, 1: array<string,string>} [params, headers]
	 */
	public static function apply( OpenIDConnectClientConfig $config, array $params ): array {
		$headers = [ 'Content-Type' => 'application/x-www-form-urlencoded' ];

		if( $config->clientSecret === '' ) {
			$params['client_id'] = $config->clientId;
		} else {
			$headers['Authorization'] = 'Basic ' . base64_encode(rawurlencode($config->clientId) . ':' . rawurlencode($config->clientSecret));
		}

		return [ $params, $headers ];
	}

}
