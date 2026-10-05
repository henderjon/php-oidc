<?php

namespace Oidc;

use Oidc\Exceptions\TokenRequestException;
use Oidc\Fakes\ArrayLogger;
use Oidc\Fakes\FixedClock;
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
		$this->assertNull($records[0]['context']['state'], 'no state was passed in - not a missing value, there is nothing to correlate with');
	}

	public function testLogsTheGivenStateForCorrelationWithTheRestOfTheFlow(): void {
		$config = new OpenIDConnectClientConfig('the-client-id', 'the-client-secret', 'https://example.com/callback');
		$logger = new ArrayLogger;

		ClientAuthenticator::apply($config, [ 'grant_type' => 'authorization_code' ], $logger, 'the-flow-state');

		$this->assertSame('the-flow-state', $logger->recordsAt(LogLevel::DEBUG)[0]['context']['state']);
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
		$this->assertNull($records[0]['context']['state']);
	}

	public function testPublicClientLogsAuthenticatingWithNoSecret(): void {
		$config = new OpenIDConnectClientConfig('the-client-id', '', 'https://example.com/callback');
		$logger = new ArrayLogger;

		ClientAuthenticator::apply($config, [ 'grant_type' => 'authorization_code' ], $logger);

		$records = $logger->recordsAt(LogLevel::DEBUG);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: authenticating as a public client with no client secret', $records[0]['message']);
		$this->assertSame('the-client-id', $records[0]['context']['client_id']);
		$this->assertNull($records[0]['context']['state']);
	}

	private const JWT_SECRET  = 'a-client-secret-that-is-long-enough-for-hs256';
	private const AUDIENCE     = 'https://issuer.example.com/token';
	private const ASSERTION_AT = 1_700_000_000;

	private function jwtConfig( string $secret = self::JWT_SECRET ): OpenIDConnectClientConfig {
		return (new OpenIDConnectClientConfig('the-client-id', $secret, 'https://example.com/callback'))
			->withClientAuthMethod(ClientAuthMethod::ClientSecretJwt);
	}

	private function fixedClock(): FixedClock {
		return new FixedClock(new \DateTimeImmutable('@' . self::ASSERTION_AT));
	}

	/**
	 * @return array{0: array<string,mixed>, 1: array<string,mixed>, 2: bool} [header, claims, signatureIsValid]
	 */
	private function decodeAssertion( string $jwt, string $secret = self::JWT_SECRET ): array {
		[ $header, $claims, $signature ] = explode('.', $jwt);

		$decode = static fn ( string $segment ): string => base64_decode(strtr($segment, '-_', '+/'));
		$expected = rtrim(strtr(base64_encode(hash_hmac('sha256', $header . '.' . $claims, $secret, true)), '+/', '-_'), '=');

		return [ json_decode($decode($header), true), json_decode($decode($claims), true), hash_equals($expected, $signature) ];
	}

	/**
	 * @return array<string,mixed>
	 */
	private function applyJwt( ?OpenIDConnectClientConfig $config = null, ?ArrayLogger $logger = null ): array {
		[ $params, $headers ] = ClientAuthenticator::apply(
			$config ?? $this->jwtConfig(),
			[ 'grant_type' => 'client_credentials' ],
			$logger ?? new ArrayLogger,
			null,
			self::AUDIENCE,
			$this->fixedClock(),
		);

		return [ $params, $headers ];
	}

	public function testClientSecretJwtSendsASignedAssertionInsteadOfTheSecret(): void {
		[ $params, $headers ] = $this->applyJwt();

		$this->assertSame('urn:ietf:params:oauth:client-assertion-type:jwt-bearer', $params['client_assertion_type']);
		$this->assertSame('the-client-id', $params['client_id']);
		$this->assertSame('client_credentials', $params['grant_type'], 'must keep the caller\'s own params');
		$this->assertArrayNotHasKey('client_secret', $params);
		$this->assertArrayNotHasKey('Authorization', $headers);
		$this->assertSame('application/x-www-form-urlencoded', $headers['Content-Type']);
		$this->assertStringNotContainsString(self::JWT_SECRET, json_encode($params));
	}

	public function testClientSecretJwtAssertionCarriesTheRequiredClaims(): void {
		[ $params ] = $this->applyJwt();

		[ $header, $claims, $signatureIsValid ] = $this->decodeAssertion($params['client_assertion']);

		$this->assertSame('HS256', $header['alg']);
		$this->assertTrue($signatureIsValid, 'must verify against the client secret');
		$this->assertSame('the-client-id', $claims['iss']);
		$this->assertSame('the-client-id', $claims['sub']);
		$this->assertSame(self::AUDIENCE, $claims['aud']);
		$this->assertSame(self::ASSERTION_AT, $claims['iat']);
		$this->assertMatchesRegularExpression('/^[0-9a-f]{32}$/', $claims['jti']);
	}

	public function testClientSecretJwtAssertionIsShortLived(): void {
		[ $params ] = $this->applyJwt();

		[ , $claims ] = $this->decodeAssertion($params['client_assertion']);

		$this->assertSame(self::ASSERTION_AT + 60, $claims['exp']);
	}

	public function testClientSecretJwtUsesADifferentJtiEveryTime(): void {
		$jtis = [];

		for( $i = 0; $i < 50; $i++ ) {
			[ $params ] = $this->applyJwt();
			$jtis[]     = $this->decodeAssertion($params['client_assertion'])[1]['jti'];
		}

		$this->assertCount(50, array_unique($jtis));
	}

	public function testClientSecretJwtAssertionDoesNotVerifyAgainstAnotherSecret(): void {
		[ $params ] = $this->applyJwt();

		[ , , $signatureIsValid ] = $this->decodeAssertion($params['client_assertion'], 'a-different-secret-that-is-also-long-enough');

		$this->assertFalse($signatureIsValid);
	}

	public function testClientSecretJwtOnAPublicClientStillIdentifiesViaClientIdOnly(): void {
		$config = $this->jwtConfig('');

		[ $params, $headers ] = $this->applyJwt($config);

		$this->assertSame('the-client-id', $params['client_id']);
		$this->assertArrayNotHasKey('client_assertion', $params);
		$this->assertArrayNotHasKey('Authorization', $headers);
	}

	public function testClientSecretJwtRejectsASecretTooShortForHs256(): void {
		$logger = new ArrayLogger;

		try {
			$this->applyJwt($this->jwtConfig('too-short'), $logger);
			$this->fail('Expected TokenRequestException to be thrown');
		} catch( TokenRequestException $e ) {
			$this->assertSame('Client secret is too short to sign a client_secret_jwt assertion with HS256', $e->getMessage());
			$this->assertStringNotContainsString('too-short', $e->getMessage());
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertFalse($records[0]['context']['security_relevant']);
		$this->assertStringNotContainsString('too-short', json_encode($logger->records));
	}

	public function testClientSecretJwtRejectsAMissingAudience(): void {
		$logger = new ArrayLogger;

		try {
			ClientAuthenticator::apply($this->jwtConfig(), [], $logger);
			$this->fail('Expected TokenRequestException to be thrown');
		} catch( TokenRequestException $e ) {
			$this->assertStringContainsString('audience', $e->getMessage());
		}

		$this->assertCount(1, $logger->recordsAt(LogLevel::ERROR));
	}

	public function testClientSecretJwtLogsTheJtiButNeitherTheAssertionNorTheSecret(): void {
		$logger = new ArrayLogger;

		[ $params ] = $this->applyJwt(logger: $logger);

		$records = $logger->recordsAt(LogLevel::DEBUG);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: authenticating with client_secret_jwt', $records[0]['message']);
		$this->assertSame($this->decodeAssertion($params['client_assertion'])[1]['jti'], $records[0]['context']['jti']);

		$serialized = json_encode($logger->records);
		$this->assertStringNotContainsString($params['client_assertion'], $serialized);
		$this->assertStringNotContainsString(self::JWT_SECRET, $serialized);
	}

}
