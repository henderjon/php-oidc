<?php

namespace Oidc;

use PHPUnit\Framework\TestCase;

class OpenIDConnectClientConfigTest extends TestCase {

	private function makeConfig(): OpenIDConnectClientConfig {
		return new OpenIDConnectClientConfig(
			clientId: 'client-id',
			clientSecret: 'client-secret',
			redirectUrl: 'https://example.com/callback',
		);
	}

	public function testConstructorDefaults(): void {
		$config = $this->makeConfig();

		$this->assertSame('client-id', $config->clientId);
		$this->assertSame('client-secret', $config->clientSecret);
		$this->assertSame('https://example.com/callback', $config->redirectUrl);
		$this->assertNull($config->providerUrl);
		$this->assertNull($config->issuer);
		$this->assertSame([], $config->scopes);
		$this->assertSame([], $config->endpointOverrides);
		$this->assertSame([], $config->extraAuthParams);
		$this->assertTrue($config->verifyTls);
		$this->assertNull($config->audience);
	}

	public function testWithClientId(): void {
		$config = $this->makeConfig();
		$new    = $config->withClientId('other-id');

		$this->assertSame('client-id', $config->clientId, 'original must be unchanged');
		$this->assertSame('other-id', $new->clientId);
		$this->assertSame($config->clientSecret, $new->clientSecret);
	}

	public function testWithClientSecret(): void {
		$new = $this->makeConfig()->withClientSecret('other-secret');

		$this->assertSame('other-secret', $new->clientSecret);
	}

	public function testWithRedirectUrl(): void {
		$new = $this->makeConfig()->withRedirectUrl('https://example.com/other');

		$this->assertSame('https://example.com/other', $new->redirectUrl);
	}

	public function testWithProviderUrl(): void {
		$config = $this->makeConfig();
		$new    = $config->withProviderUrl('https://issuer.example.com');

		$this->assertNull($config->providerUrl);
		$this->assertSame('https://issuer.example.com', $new->providerUrl);
	}

	public function testWithProviderUrlCanClearToNull(): void {
		$new = $this->makeConfig()->withProviderUrl('https://issuer.example.com')->withProviderUrl(null);

		$this->assertNull($new->providerUrl);
	}

	public function testWithIssuer(): void {
		$new = $this->makeConfig()->withIssuer('https://issuer.example.com');

		$this->assertSame('https://issuer.example.com', $new->issuer);
	}

	public function testWithScopesMergesAndDeduplicates(): void {
		$config = $this->makeConfig()->withScopes([ 'openid', 'email' ]);
		$new    = $config->withScopes([ 'email', 'profile' ]);

		$this->assertSame([ 'openid', 'email' ], $config->scopes, 'original must be unchanged');
		$this->assertSame([ 'openid', 'email', 'profile' ], $new->scopes);
	}

	public function testWithEndpointOverridesMerges(): void {
		$config = $this->makeConfig()->withEndpointOverrides([ 'authorization_endpoint' => 'https://a' ]);
		$new    = $config->withEndpointOverrides([ 'jwks_uri' => 'https://b' ]);

		$this->assertSame([ 'authorization_endpoint' => 'https://a' ], $config->endpointOverrides, 'original must be unchanged');
		$this->assertSame(
			[ 'authorization_endpoint' => 'https://a', 'jwks_uri' => 'https://b' ],
			$new->endpointOverrides,
		);
	}

	public function testWithEndpointOverridesLaterValueWins(): void {
		$config = $this->makeConfig()->withEndpointOverrides([ 'jwks_uri' => 'https://a' ]);
		$new    = $config->withEndpointOverrides([ 'jwks_uri' => 'https://b' ]);

		$this->assertSame('https://b', $new->endpointOverrides['jwks_uri']);
	}

	public function testWithExtraAuthParamsMerges(): void {
		$config = $this->makeConfig()->withExtraAuthParams([ 'prompt' => 'none' ]);
		$new    = $config->withExtraAuthParams([ 'response_mode' => 'form_post' ]);

		$this->assertSame([ 'prompt' => 'none' ], $config->extraAuthParams, 'original must be unchanged');
		$this->assertSame(
			[ 'prompt' => 'none', 'response_mode' => 'form_post' ],
			$new->extraAuthParams,
		);
	}

	public function testWithVerifyTls(): void {
		$new = $this->makeConfig()->withVerifyTls(false);

		$this->assertFalse($new->verifyTls);
	}

	public function testWithAudience(): void {
		$config = $this->makeConfig();
		$new    = $config->withAudience('the-audience');

		$this->assertNull($config->audience, 'original must be unchanged');
		$this->assertSame('the-audience', $new->audience);
	}

	public function testWithAudienceCanClearToNull(): void {
		$new = $this->makeConfig()->withAudience('the-audience')->withAudience(null);

		$this->assertNull($new->audience);
	}

	public function testWithAudienceAcceptsAList(): void {
		$new = $this->makeConfig()->withAudience([ 'the-client-id', 'the-resource-audience' ]);

		$this->assertSame([ 'the-client-id', 'the-resource-audience' ], $new->audience);
	}

	public function testWithersPreserveAudience(): void {
		$config = $this->makeConfig()->withAudience('the-audience');

		$this->assertSame('the-audience', $config->withScopes([ 'email' ])->audience);
		$this->assertSame('the-audience', $config->withVerifyTls(false)->audience);
		$this->assertSame('the-audience', $config->withIssuer('https://issuer.example.com')->audience);
	}

}
