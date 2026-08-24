<?php

namespace Oidc;

use PHPUnit\Framework\TestCase;

class UrlPolicyTest extends TestCase {

	private UrlPolicy $urlPolicy;

	protected function setUp(): void {
		$this->urlPolicy = new UrlPolicy;
	}

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
		$this->assertTrue($this->urlPolicy->isAllowed('https://issuer.example.com/token', $this->config()));
	}

	public function testHttpIsDisallowedByDefault(): void {
		$this->assertFalse($this->urlPolicy->isAllowed('http://issuer.example.com/token', $this->config()));
	}

	public function testHttpIsAllowedWhenInsecureSchemesAreOptedInto(): void {
		$config = $this->config(allowInsecureSchemes: true);

		$this->assertTrue($this->urlPolicy->isAllowed('http://issuer.example.com/token', $config));
	}

	public function testOtherSchemesAreAlwaysDisallowedEvenWithInsecureSchemesAllowed(): void {
		$config = $this->config(allowInsecureSchemes: true);

		$this->assertFalse($this->urlPolicy->isAllowed('file:///etc/passwd', $config));
		$this->assertFalse($this->urlPolicy->isAllowed('gopher://issuer.example.com/token', $config));
	}

	public function testMalformedUrlsAreDisallowed(): void {
		$config = $this->config();

		$this->assertFalse($this->urlPolicy->isAllowed('not-a-url', $config));
		$this->assertFalse($this->urlPolicy->isAllowed('https:///no-host', $config));
	}

	public function testNoAllowlistPermitsAnyHost(): void {
		$this->assertTrue($this->urlPolicy->isAllowed('https://issuer.example.com/token', $this->config()));
		$this->assertTrue($this->urlPolicy->isAllowed('https://anywhere.example.net/token', $this->config()));
	}

	public function testAllowlistPermitsAMatchingHost(): void {
		$config = $this->config(allowedHosts: [ 'issuer.example.com' ]);

		$this->assertTrue($this->urlPolicy->isAllowed('https://issuer.example.com/token', $config));
	}

	public function testAllowlistRejectsANonMatchingHost(): void {
		$config = $this->config(allowedHosts: [ 'issuer.example.com' ]);

		$this->assertFalse($this->urlPolicy->isAllowed('https://attacker.example.net/token', $config));
	}

	public function testAllowlistIsCheckedInAdditionToScheme(): void {
		$config = $this->config(allowedHosts: [ 'issuer.example.com' ]);

		// A matching host on a disallowed scheme must still fail - the checks are additive,
		// not either/or.
		$this->assertFalse($this->urlPolicy->isAllowed('http://issuer.example.com/token', $config));
	}

}
