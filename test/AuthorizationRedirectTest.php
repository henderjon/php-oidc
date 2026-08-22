<?php

namespace Henderjon\Oidc;

use PHPUnit\Framework\TestCase;

class AuthorizationRedirectTest extends TestCase {

	public function testConstructor(): void {
		$redirect = new AuthorizationRedirect('https://example.com/authorize?state=abc');

		$this->assertSame('https://example.com/authorize?state=abc', $redirect->url);
	}

}
