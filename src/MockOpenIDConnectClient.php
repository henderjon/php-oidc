<?php

namespace Henderjon\Oidc;

use Henderjon\Oidc\Exceptions\AuthenticationFailedException;
use Henderjon\Oidc\Interfaces\TokenGrantClientInterface;
use Henderjon\Oidc\Interfaces\UserInfoClientInterface;

/**
 * A hand-written fake for a consuming application's own controller tests -
 * no network, no cache, no real cryptography. Every canned result is a
 * public property so a test can override just the ones it cares about
 * before exercising the controller.
 *
 * Defaults to a successful outcome everywhere, since login success is the
 * path most controller tests exercise; set `*Exception` to simulate a
 * failure instead.
 *
 * UserInfoClientInterface already extends AuthorizationFlowClientInterface,
 * so implementing it here covers both without listing the base interface
 * separately.
 */
class MockOpenIDConnectClient implements
	TokenGrantClientInterface,
	UserInfoClientInterface {

	public string $redirectUrl = 'https://example.com/mock-authorize';

	public AuthenticationResult $authenticationResult;

	public ?AuthenticationFailedException $authenticationException = null;

	public TokenResult $tokenResult;

	public Claims $userInfo;

	public function __construct() {
		$this->authenticationResult = new AuthenticationResult('mock-id-token', new Claims([ 'sub' => 'mock-user' ]));
		$this->tokenResult          = new TokenResult([ 'access_token' => 'mock-access-token' ]);
		$this->userInfo             = new Claims([ 'sub' => 'mock-user' ]);
	}

	public function buildAuthorizationCodeRedirect( OpenIDConnectClientConfig $config ): AuthorizationRedirect {
		return new AuthorizationRedirect($this->redirectUrl);
	}

	public function completeAuthorizationCodeFlow(
		OpenIDConnectClientConfig $config,
		IncomingAuthorizationResponse $response,
	): AuthenticationResult {
		return $this->authenticateOrThrow();
	}

	public function buildImplicitFlowRedirect( OpenIDConnectClientConfig $config ): AuthorizationRedirect {
		return new AuthorizationRedirect($this->redirectUrl);
	}

	public function completeImplicitFlow(
		OpenIDConnectClientConfig $config,
		IncomingAuthorizationResponse $response,
	): AuthenticationResult {
		return $this->authenticateOrThrow();
	}

	public function requestClientCredentialsToken( OpenIDConnectClientConfig $config, array $scopes = [] ): TokenResult {
		return $this->tokenResult;
	}

	public function fetchUserInfo( OpenIDConnectClientConfig $config, string $accessToken ): Claims {
		return $this->userInfo;
	}

	private function authenticateOrThrow(): AuthenticationResult {
		if( $this->authenticationException !== null ) {
			throw $this->authenticationException;
		}

		return $this->authenticationResult;
	}

}
