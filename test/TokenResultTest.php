<?php

namespace Oidc;

use Oidc\Exceptions\TokenRequestException;
use PHPUnit\Framework\TestCase;

class TokenResultTest extends TestCase {

	public function testConstructWithFullResponse(): void {
		$result = new TokenResult([
			'access_token'  => 'the-access-token',
			'token_type'    => 'Bearer',
			'expires_in'    => 3600,
			'refresh_token' => 'the-refresh-token',
			'id_token'      => 'the-id-token',
			'scope'         => 'openid email',
		]);

		$this->assertSame('the-access-token', $result->accessToken);
		$this->assertSame('Bearer', $result->tokenType);
		$this->assertSame(3600, $result->expiresIn);
		$this->assertSame('the-refresh-token', $result->refreshToken);
		$this->assertSame('the-id-token', $result->idToken);
		$this->assertSame('openid email', $result->scope);
	}

	public function testConstructDefaultsTokenTypeToBearer(): void {
		$result = new TokenResult([ 'access_token' => 'the-access-token' ]);

		$this->assertSame('Bearer', $result->tokenType);
		$this->assertNull($result->expiresIn);
		$this->assertNull($result->refreshToken);
		$this->assertNull($result->idToken);
		$this->assertNull($result->scope);
	}

	public function testConstructThrowsWhenAccessTokenMissing(): void {
		$this->expectException(TokenRequestException::class);

		new TokenResult([ 'token_type' => 'Bearer' ]);
	}

	public function testConstructThrowsWhenAccessTokenEmpty(): void {
		$this->expectException(TokenRequestException::class);

		new TokenResult([ 'access_token' => '' ]);
	}

}
