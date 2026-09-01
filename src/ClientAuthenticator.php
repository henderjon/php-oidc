<?php

namespace Oidc;

/**
 * Applies one of OpenID Connect Core 1.0 §9's Client Authentication methods (see
 * ClientAuthMethod) to a token/introspection/revocation request - HTTP Basic or client
 * credentials in the body, per `$config->clientAuthMethod` - falling back to identifying the
 * client via a bare `client_id` in the body for a public client with no secret, regardless of
 * which method is configured.
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

			return [ $params, $headers ];
		}

		if( $config->clientAuthMethod === ClientAuthMethod::Post ) {
			$params['client_id']     = $config->clientId;
			$params['client_secret'] = $config->clientSecret;

			return [ $params, $headers ];
		}

		// RFC 6749 §2.3.1 requires the client id and secret to each be percent-encoded before
		// joining with ":" and base64-encoding - plain HTTP Basic (RFC 7617) has no such step,
		// but OAuth2 adds it so a ":"/"@"/"%" inside either value cannot be mistaken for the
		// credential separator. rawurlencode(), not urlencode() - Appendix B's encoding is
		// "application/x-www-form-urlencoded" with one override, escaping space as %20 rather
		// than "+".
		$headers['Authorization'] = 'Basic ' . base64_encode(rawurlencode($config->clientId) . ':' . rawurlencode($config->clientSecret));

		return [ $params, $headers ];
	}

}
