<?php

namespace Oidc;

use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Interfaces\AuthorizationFlowClientInterface;
use Oidc\Interfaces\RefreshTokenClientInterface;
use Oidc\Interfaces\TokenGrantClientInterface;
use Oidc\Interfaces\UserInfoClientInterface;
use PHPUnit\Framework\TestCase;

class MockOpenIDConnectClientTest extends TestCase {

	private function config(): OpenIDConnectClientConfig {
		return new OpenIDConnectClientConfig('client-id', 'client-secret', 'https://example.com/callback');
	}

	public function testImplementsEveryCapabilityInterface(): void {
		$mock = new MockOpenIDConnectClient;

		$this->assertInstanceOf(AuthorizationFlowClientInterface::class, $mock);
		$this->assertInstanceOf(TokenGrantClientInterface::class, $mock);
		$this->assertInstanceOf(UserInfoClientInterface::class, $mock);
		$this->assertInstanceOf(RefreshTokenClientInterface::class, $mock);
	}

	public function testBuildRedirectsReturnTheConfiguredUrl(): void {
		$mock              = new MockOpenIDConnectClient;
		$mock->redirectUrl = 'https://example.com/configured';

		$this->assertSame('https://example.com/configured', $mock->buildAuthorizationCodeRedirect($this->config())->url);
		$this->assertSame('https://example.com/configured', $mock->buildImplicitFlowRedirect($this->config())->url);
	}

	public function testCompleteFlowsReturnTheConfiguredAuthenticationResultByDefault(): void {
		$mock     = new MockOpenIDConnectClient;
		$response = new IncomingAuthorizationResponse([]);

		$this->assertSame('mock-user', $mock->completeAuthorizationCodeFlow($this->config(), $response)->claims->get('sub'));
		$this->assertSame('mock-user', $mock->completeImplicitFlow($this->config(), $response)->claims->get('sub'));
	}

	public function testCompleteFlowsUseAnOverriddenAuthenticationResult(): void {
		$mock                       = new MockOpenIDConnectClient;
		$mock->authenticationResult = new AuthenticationResult('other-id-token', new Claims([ 'sub' => 'other-user' ]));

		$result = $mock->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([]));

		$this->assertSame('other-user', $result->claims->get('sub'));
	}

	public function testCompleteFlowsThrowTheConfiguredException(): void {
		$mock                          = new MockOpenIDConnectClient;
		$mock->authenticationException = new AuthenticationFailedException('simulated failure');

		$this->expectExceptionObject($mock->authenticationException);

		$mock->completeAuthorizationCodeFlow($this->config(), new IncomingAuthorizationResponse([]));
	}

	public function testRequestClientCredentialsTokenReturnsTheConfiguredTokenResult(): void {
		$mock              = new MockOpenIDConnectClient;
		$mock->tokenResult = new TokenResult([ 'access_token' => 'configured-access-token' ]);

		$this->assertSame('configured-access-token', $mock->requestClientCredentialsToken($this->config())->accessToken);
	}

	public function testFetchUserInfoReturnsTheConfiguredClaims(): void {
		$mock           = new MockOpenIDConnectClient;
		$mock->userInfo = new Claims([ 'sub' => 'configured-user' ]);

		$this->assertSame('configured-user', $mock->fetchUserInfo($this->config(), 'access-token', 'configured-user')->get('sub'));
	}

	public function testRefreshReturnsTheConfiguredAuthenticationResult(): void {
		$mock                       = new MockOpenIDConnectClient;
		$mock->authenticationResult = new AuthenticationResult('refreshed-id-token', new Claims([ 'sub' => 'refreshed-user' ]));

		$result = $mock->refresh($this->config(), 'refresh-token', 'original-id-token', new Claims([ 'sub' => 'mock-user' ]));

		$this->assertSame('refreshed-user', $result->claims->get('sub'));
	}

	public function testRefreshThrowsTheConfiguredException(): void {
		$mock                          = new MockOpenIDConnectClient;
		$mock->authenticationException = new AuthenticationFailedException('simulated refresh failure');

		$this->expectExceptionObject($mock->authenticationException);

		$mock->refresh($this->config(), 'refresh-token', 'original-id-token', new Claims([ 'sub' => 'mock-user' ]));
	}

}
