<?php

namespace Oidc;

use Oidc\Fakes\ArrayLogger;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

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

	public function testDoesNotLogAtAllWhenNoLoggerIsGiven(): void {
		// The default NullLogger must not throw or otherwise misbehave for a caller that does
		// not care about this class's debug logging - only exercised implicitly by every test
		// above that omits the third argument, but worth asserting directly once.
		$config = new OpenIDConnectClientConfig('the-client-id', 'the-client-secret', 'https://example.com/callback');

		[ $params, $headers ] = ClientAuthenticator::apply($config, [ 'grant_type' => 'client_credentials' ]);

		$this->assertArrayHasKey('grant_type', $params);
		$this->assertArrayHasKey('Authorization', $headers);
	}

	public function testBasicMethodLogsWhichMethodWasChosenWithoutTheSecret(): void {
		$config = new OpenIDConnectClientConfig('the-client-id', 'the-client-secret', 'https://example.com/callback');
		$logger = new ArrayLogger;

		ClientAuthenticator::apply($config, [ 'grant_type' => 'client_credentials' ], $logger);

		$records = $logger->recordsAt(LogLevel::DEBUG);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: authenticating with client_secret_basic', $records[0]['message']);
		$this->assertSame('the-client-id', $records[0]['context']['client_id']);
		$this->assertArrayNotHasKey('client_secret', $records[0]['context']);
	}

	public function testPostMethodLogsWhichMethodWasChosenWithoutTheSecret(): void {
		$config = (new OpenIDConnectClientConfig('the-client-id', 'the-client-secret', 'https://example.com/callback'))
			->withClientAuthMethod(ClientAuthMethod::Post);
		$logger = new ArrayLogger;

		ClientAuthenticator::apply($config, [ 'grant_type' => 'client_credentials' ], $logger);

		$records = $logger->recordsAt(LogLevel::DEBUG);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: authenticating with client_secret_post', $records[0]['message']);
		$this->assertSame('the-client-id', $records[0]['context']['client_id']);
		$this->assertArrayNotHasKey('client_secret', $records[0]['context']);
	}

	public function testPublicClientLogsAuthenticatingWithNoSecret(): void {
		$config = new OpenIDConnectClientConfig('the-client-id', '', 'https://example.com/callback');
		$logger = new ArrayLogger;

		ClientAuthenticator::apply($config, [ 'grant_type' => 'authorization_code' ], $logger);

		$records = $logger->recordsAt(LogLevel::DEBUG);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: authenticating as a public client with no client secret', $records[0]['message']);
		$this->assertSame('the-client-id', $records[0]['context']['client_id']);
	}

}
