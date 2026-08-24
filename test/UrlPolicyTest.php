<?php

namespace Oidc;

use PHPUnit\Framework\TestCase;

class UrlPolicyTest extends TestCase {

	private function config( bool $allowInsecureSchemes = false, ?array $allowedHosts = null ): OpenIDConnectClientConfig {
		return new OpenIDConnectClientConfig(
			clientId: 'the-client-id',
			clientSecret: 'the-client-secret',
			redirectUrl: 'https://example.com/callback',
			allowInsecureSchemes: $allowInsecureSchemes,
			allowedHosts: $allowedHosts,
		);
	}

	public function testHttpsIsAllowedByDefault(): void {
		$this->assertTrue(UrlPolicy::isAllowed('https://issuer.example.com/token', $this->config()));
	}

	public function testHttpIsDisallowedByDefault(): void {
		$this->assertFalse(UrlPolicy::isAllowed('http://issuer.example.com/token', $this->config()));
	}

	public function testHttpIsAllowedWhenInsecureSchemesAreOptedInto(): void {
		$config = $this->config(allowInsecureSchemes: true);

		$this->assertTrue(UrlPolicy::isAllowed('http://issuer.example.com/token', $config));
	}

	public function testOtherSchemesAreAlwaysDisallowedEvenWithInsecureSchemesAllowed(): void {
		$config = $this->config(allowInsecureSchemes: true);

		$this->assertFalse(UrlPolicy::isAllowed('file:///etc/passwd', $config));
		$this->assertFalse(UrlPolicy::isAllowed('gopher://issuer.example.com/token', $config));
	}

	public function testMalformedUrlsAreDisallowed(): void {
		$config = $this->config();

		$this->assertFalse(UrlPolicy::isAllowed('not-a-url', $config));
		$this->assertFalse(UrlPolicy::isAllowed('https:///no-host', $config));
	}

	public function testNoAllowlistPermitsAnyHost(): void {
		$this->assertTrue(UrlPolicy::isAllowed('https://issuer.example.com/token', $this->config()));
		$this->assertTrue(UrlPolicy::isAllowed('https://anywhere.example.net/token', $this->config()));
	}

	public function testAllowlistPermitsAMatchingHost(): void {
		$config = $this->config(allowedHosts: [ 'issuer.example.com' ]);

		$this->assertTrue(UrlPolicy::isAllowed('https://issuer.example.com/token', $config));
	}

	public function testAllowlistRejectsANonMatchingHost(): void {
		$config = $this->config(allowedHosts: [ 'issuer.example.com' ]);

		$this->assertFalse(UrlPolicy::isAllowed('https://attacker.example.net/token', $config));
	}

	public function testAllowlistIsCheckedInAdditionToScheme(): void {
		$config = $this->config(allowedHosts: [ 'issuer.example.com' ]);

		// A matching host on a disallowed scheme must still fail - the checks are additive,
		// not either/or.
		$this->assertFalse(UrlPolicy::isAllowed('http://issuer.example.com/token', $config));
	}

}
