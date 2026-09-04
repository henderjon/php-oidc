<?php

namespace Oidc;

use Oidc\Fakes\ArrayLogger;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

class UrlPolicyTest extends TestCase {

	private UrlPolicy $urlPolicy;

	protected function setUp(): void {
		$this->urlPolicy = new UrlPolicy;
	}

	private function config(
		bool $allowInsecureSchemes = false,
		?array $allowedHosts = null,
		bool $allowAnyHost = false,
		?string $providerUrl = null,
		?string $issuer = null,
	): OpenIDConnectClientConfig {
		return new OpenIDConnectClientConfig(
			clientId: 'the-client-id',
			clientSecret: 'the-client-secret',
			redirectUrl: 'https://example.com/callback',
			providerUrl: $providerUrl,
			issuer: $issuer,
			allowInsecureSchemes: $allowInsecureSchemes,
			allowedHosts: $allowedHosts,
			allowAnyHost: $allowAnyHost,
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

	public function testNoAllowlistAndNoProviderPermitsAnyHost(): void {
		// Neither issuer nor providerUrl is set on this config - there is no discovery-driven
		// trust boundary to protect (ProviderMetadataResolver never performs discovery at all
		// without one of them), so this falls back to unrestricted rather than rejecting
		// every host.
		$this->assertTrue($this->urlPolicy->isAllowed('https://issuer.example.com/token', $this->config()));
		$this->assertTrue($this->urlPolicy->isAllowed('https://anywhere.example.net/token', $this->config()));
	}

	public function testNoAllowlistFallsBackToTheProviderUrlHost(): void {
		$config = $this->config(providerUrl: 'https://issuer.example.com');

		$this->assertTrue($this->urlPolicy->isAllowed('https://issuer.example.com/token', $config));
		$this->assertFalse($this->urlPolicy->isAllowed('https://attacker.example.net/token', $config));
	}

	public function testNoAllowlistPrefersTheIssuerHostOverProviderUrl(): void {
		$config = $this->config(providerUrl: 'https://discovery.example.com', issuer: 'https://issuer.example.com');

		$this->assertTrue($this->urlPolicy->isAllowed('https://issuer.example.com/token', $config));
		$this->assertFalse($this->urlPolicy->isAllowed('https://discovery.example.com/token', $config));
	}

	public function testAllowAnyHostPermitsAnyHostEvenWithAProviderUrlSet(): void {
		$config = $this->config(providerUrl: 'https://issuer.example.com', allowAnyHost: true);

		$this->assertTrue($this->urlPolicy->isAllowed('https://issuer.example.com/token', $config));
		$this->assertTrue($this->urlPolicy->isAllowed('https://anywhere.example.net/token', $config));
	}

	public function testExplicitAllowlistTakesPrecedenceOverAllowAnyHost(): void {
		$config = $this->config(allowedHosts: [ 'issuer.example.com' ], allowAnyHost: true);

		$this->assertFalse($this->urlPolicy->isAllowed('https://attacker.example.net/token', $config));
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

	public function testAllowlistAcceptsASchemePrefixedEntry(): void {
		// A caller pasting a full endpoint URL into allowedHosts, scheme included, is an easy
		// mistake - the host is recovered from it rather than making every request fail
		// silently, since a bare hostname parsed from the real URL can never string-equal a
		// scheme-prefixed entry.
		$config = $this->config(allowedHosts: [ 'https://issuer.example.com' ]);

		$this->assertTrue($this->urlPolicy->isAllowed('https://issuer.example.com/token', $config));
	}

	public function testAllowlistStillRejectsANonMatchingHostWhenEntryIsSchemePrefixed(): void {
		$config = $this->config(allowedHosts: [ 'https://issuer.example.com' ]);

		$this->assertFalse($this->urlPolicy->isAllowed('https://attacker.example.net/token', $config));
	}

	public function testASchemePrefixedAllowlistEntryDoesNotGrantThatScheme(): void {
		// The scheme on an allowedHosts entry is never consulted - scheme is enforced once,
		// globally, via allowInsecureSchemes, never per host. An http:// entry must not act as
		// a backdoor into allowing http for that host.
		$config = $this->config(allowedHosts: [ 'http://issuer.example.com' ]);

		$this->assertFalse($this->urlPolicy->isAllowed('http://issuer.example.com/token', $config));
	}

	public function testASchemePrefixedAllowlistEntryLogsTheCorrectionAtDebugLevel(): void {
		$logger    = new ArrayLogger;
		$urlPolicy = new UrlPolicy($logger);
		$config    = $this->config(allowedHosts: [ 'https://issuer.example.com' ]);

		$urlPolicy->isAllowed('https://issuer.example.com/token', $config);

		$records = $logger->recordsAt(LogLevel::DEBUG);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: an allowedHosts entry looks like a full URL rather than a bare hostname - using the host recovered from it', $records[0]['message']);
		$this->assertSame('https://issuer.example.com', $records[0]['context']['configured_entry']);
		$this->assertSame('issuer.example.com', $records[0]['context']['recovered_host']);
	}

	public function testABareHostnameAllowlistEntryDoesNotLogAnything(): void {
		$logger    = new ArrayLogger;
		$urlPolicy = new UrlPolicy($logger);
		$config    = $this->config(allowedHosts: [ 'issuer.example.com' ]);

		$urlPolicy->isAllowed('https://issuer.example.com/token', $config);

		$this->assertSame([], $logger->records);
	}

	public function testNoAllowlistAtAllDoesNotLogAnything(): void {
		$logger    = new ArrayLogger;
		$urlPolicy = new UrlPolicy($logger);

		$urlPolicy->isAllowed('https://issuer.example.com/token', $this->config());

		$this->assertSame([], $logger->records);
	}

}
