<?php

namespace Henderjon\Oidc;

use PHPUnit\Framework\TestCase;

class ClientAuthenticatorTest extends TestCase {

	public function testConfidentialClientUsesHttpBasic(): void {
		$config = new OpenIDConnectClientConfig('the-client-id', 'the-client-secret', 'https://example.com/callback');

		[ $params, $headers ] = ClientAuthenticator::apply($config, [ 'grant_type' => 'client_credentials' ]);

		$this->assertSame([ 'grant_type' => 'client_credentials' ], $params, 'must not add client_id to the body for a confidential client');
		$this->assertSame(
			'Basic ' . base64_encode('the-client-id:the-client-secret'),
			$headers['Authorization'],
		);
	}

	public function testPublicClientIdentifiesViaClientIdInBody(): void {
		$config = new OpenIDConnectClientConfig('the-client-id', '', 'https://example.com/callback');

		[ $params, $headers ] = ClientAuthenticator::apply($config, [ 'grant_type' => 'authorization_code' ]);

		$this->assertSame('the-client-id', $params['client_id']);
		$this->assertArrayNotHasKey('Authorization', $headers);
	}

	public function testAlwaysSetsFormEncodedContentType(): void {
		$config = new OpenIDConnectClientConfig('the-client-id', 'the-client-secret', 'https://example.com/callback');

		[ , $headers ] = ClientAuthenticator::apply($config, []);

		$this->assertSame('application/x-www-form-urlencoded', $headers['Content-Type']);
	}

}
