<?php

namespace Oidc;

use Oidc\Exceptions\TokenRequestException;
use PHPUnit\Framework\TestCase;

class TokenRequestExceptionTest extends TestCase {

	public function testGetStateForwardsToTheBaseException(): void {
		$exception = new TokenRequestException('token request failed', 400, 'raw body', 'the-flow-state');

		$this->assertSame(400, $exception->getHttpStatus());
		$this->assertSame('raw body', $exception->getRawBody());
		$this->assertSame('the-flow-state', $exception->getState());
	}

	public function testGetStateDefaultsToNull(): void {
		$exception = new TokenRequestException('token request failed');

		$this->assertNull($exception->getState());
	}

	public function testGetProviderErrorDefaultsToNull(): void {
		$exception = new TokenRequestException('token request failed');

		$this->assertNull($exception->getProviderError());
	}

	public function testGetProviderErrorReturnsTheGivenValue(): void {
		$providerError = new ProviderError('invalid_grant', 'The authorization code has expired');
		$exception      = new TokenRequestException('token request failed', providerError: $providerError);

		$this->assertSame($providerError, $exception->getProviderError());
	}

}
