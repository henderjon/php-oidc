<?php

namespace Oidc;

use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Applies one of OpenID Connect Core 1.0 §9's Client Authentication methods (see
 * ClientAuthMethod) to a token/introspection/revocation request - HTTP Basic or client
 * credentials in the body, per `$config->clientAuthMethod` - falling back to identifying the
 * client via a bare `client_id` in the body for a public client with no secret, regardless of
 * which method is configured.
 *
 * `$logger` is optional (defaulting to a no-op) rather than a constructor dependency, since this
 * class stays static and stateless - every other collaborator that logs is a value the factory
 * wires once; this one is called straight from TokenEndpointClient, which already has its own
 * logger to hand it. Logs which method it picked and how - a mismatch with what an IdP expects
 * (Basic vs. Post, or `none` for a client the provider still expects credentials from) is a
 * common integration failure, and there is otherwise no way to confirm which one actually went
 * out without inspecting the wire. `client_secret` is never logged whole, even at debug level -
 * it is a long-lived, static credential, not a one-time code or short-lived token, so repeatedly
 * logging even a partial reveal of it still accumulates real exposure over the client's entire
 * lifetime. See Redact for the same partial-reveal handling used everywhere else in this module.
 */
final class ClientAuthenticator {

	/**
	 * @param array<string,string|list<string>> $params
	 * @return array{0: array<string,string|list<string>>, 1: array<string,string>} [params, headers]
	 */
	public static function apply( OpenIDConnectClientConfig $config, array $params, LoggerInterface $logger = new NullLogger ): array {
		$headers = [ 'Content-Type' => 'application/x-www-form-urlencoded' ];

		if( $config->clientSecret === '' ) {
			$params['client_id'] = $config->clientId;

			$logger->debug('OIDC: authenticating as a public client with no client secret', [ 'client_id' => $config->clientId ]);

			return [ $params, $headers ];
		}

		if( $config->clientAuthMethod === ClientAuthMethod::Post ) {
			$params['client_id']     = $config->clientId;
			$params['client_secret'] = $config->clientSecret;

			$logger->debug('OIDC: authenticating with client_secret_post', [ 'client_id' => $config->clientId ]);

			return [ $params, $headers ];
		}

		// RFC 6749 §2.3.1 requires the client id and secret to each be percent-encoded before
		// joining with ":" and base64-encoding - plain HTTP Basic (RFC 7617) has no such step,
		// but OAuth2 adds it so a ":"/"@"/"%" inside either value cannot be mistaken for the
		// credential separator. rawurlencode(), not urlencode() - Appendix B's encoding is
		// "application/x-www-form-urlencoded" with one override, escaping space as %20 rather
		// than "+".
		$headers['Authorization'] = 'Basic ' . base64_encode(rawurlencode($config->clientId) . ':' . rawurlencode($config->clientSecret));

		$logger->debug('OIDC: authenticating with client_secret_basic', [ 'client_id' => $config->clientId ]);

		return [ $params, $headers ];
	}

}
