<?php

namespace Henderjon\Oidc;

use PHPUnit\Framework\TestCase;

class AuthenticationResultTest extends TestCase {

	public function testConstructor(): void {
		$claims = new Claims([ 'sub' => 'user-1' ]);
		$result = new AuthenticationResult(
			idToken: 'the-id-token',
			claims: $claims,
			accessToken: 'the-access-token',
			refreshToken: 'the-refresh-token',
		);

		$this->assertSame('the-id-token', $result->idToken);
		$this->assertSame($claims, $result->claims);
		$this->assertSame('the-access-token', $result->accessToken);
		$this->assertSame('the-refresh-token', $result->refreshToken);
	}

	public function testAccessAndRefreshTokenDefaultToNull(): void {
		$result = new AuthenticationResult('the-id-token', new Claims([]));

		$this->assertNull($result->accessToken);
		$this->assertNull($result->refreshToken);
	}

}
