<?php

namespace Oidc;

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

	public function testConfidentialClientWithPostMethodSendsCredentialsInTheBody(): void {
		$config = (new OpenIDConnectClientConfig('the-client-id', 'the-client-secret', 'https://example.com/callback'))
			->withClientAuthMethod(ClientAuthMethod::Post);

		[ $params, $headers ] = ClientAuthenticator::apply($config, [ 'grant_type' => 'client_credentials' ]);

		$this->assertSame('the-client-id', $params['client_id']);
		$this->assertSame('the-client-secret', $params['client_secret']);
		$this->assertArrayNotHasKey('Authorization', $headers);
	}

	public function testConfidentialClientWithPostMethodDoesNotOverwriteExistingParams(): void {
		$config = (new OpenIDConnectClientConfig('the-client-id', 'the-client-secret', 'https://example.com/callback'))
			->withClientAuthMethod(ClientAuthMethod::Post);

		[ $params ] = ClientAuthenticator::apply($config, [ 'grant_type' => 'authorization_code', 'code' => 'the-code' ]);

		$this->assertSame('authorization_code', $params['grant_type']);
		$this->assertSame('the-code', $params['code']);
	}

	public function testPublicClientWithPostMethodStillIdentifiesViaClientIdOnly(): void {
		// A public client has no secret to send under any method - Post must not change that.
		$config = (new OpenIDConnectClientConfig('the-client-id', '', 'https://example.com/callback'))
			->withClientAuthMethod(ClientAuthMethod::Post);

		[ $params, $headers ] = ClientAuthenticator::apply($config, [ 'grant_type' => 'authorization_code' ]);

		$this->assertSame('the-client-id', $params['client_id']);
		$this->assertArrayNotHasKey('client_secret', $params);
		$this->assertArrayNotHasKey('Authorization', $headers);
	}

	public function testBasicMethodIsTheDefault(): void {
		$config = new OpenIDConnectClientConfig('the-client-id', 'the-client-secret', 'https://example.com/callback');

		$this->assertSame(ClientAuthMethod::Basic, $config->clientAuthMethod);
	}

}
