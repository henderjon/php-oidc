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
		$this->assertNull($config->audience);
		$this->assertSame(PkceMode::Disabled, $config->pkce);
		$this->assertFalse($config->allowInsecureSchemes);
		$this->assertNull($config->allowedHosts);
		$this->assertSame([ 'RS256' ], $config->allowedAlgorithms);
		$this->assertNull($config->maxTokenLifetimeSeconds);
		$this->assertFalse($config->allowUntrustedAudiences);
		$this->assertFalse($config->allowAnyHost);
		$this->assertSame(ClientAuthMethod::Basic, $config->clientAuthMethod);
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
		$this->assertSame('the-audience', $config->withAllowInsecureSchemes(true)->audience);
		$this->assertSame('the-audience', $config->withIssuer('https://issuer.example.com')->audience);
	}

	public function testWithPkce(): void {
		$config = $this->makeConfig();
		$new    = $config->withPkce(PkceMode::Required);

		$this->assertSame(PkceMode::Disabled, $config->pkce, 'original must be unchanged');
		$this->assertSame(PkceMode::Required, $new->pkce);
	}

	public function testWithAllowInsecureSchemes(): void {
		$config = $this->makeConfig();
		$new    = $config->withAllowInsecureSchemes(true);

		$this->assertFalse($config->allowInsecureSchemes, 'original must be unchanged');
		$this->assertTrue($new->allowInsecureSchemes);
	}

	public function testWithAllowedHostsReplacesRatherThanMerges(): void {
		$config = $this->makeConfig()->withAllowedHosts([ 'a.example.com' ]);
		$new    = $config->withAllowedHosts([ 'b.example.com' ]);

		$this->assertSame([ 'a.example.com' ], $config->allowedHosts, 'original must be unchanged');
		$this->assertSame([ 'b.example.com' ], $new->allowedHosts, 'must replace, not merge with the previous list');
	}

	public function testWithAllowedHostsCanClearToNull(): void {
		$new = $this->makeConfig()->withAllowedHosts([ 'a.example.com' ])->withAllowedHosts(null);

		$this->assertNull($new->allowedHosts);
	}

	public function testWithAllowedAlgorithmsReplacesRatherThanMerges(): void {
		$config = $this->makeConfig()->withAllowedAlgorithms([ 'RS256', 'PS256' ]);
		$new    = $config->withAllowedAlgorithms([ 'ES256' ]);

		$this->assertSame([ 'RS256', 'PS256' ], $config->allowedAlgorithms, 'original must be unchanged');
		$this->assertSame([ 'ES256' ], $new->allowedAlgorithms, 'must replace, not merge with the previous list');
	}

	public function testWithMaxTokenLifetimeSeconds(): void {
		$config = $this->makeConfig();
		$new    = $config->withMaxTokenLifetimeSeconds(3600);

		$this->assertNull($config->maxTokenLifetimeSeconds, 'original must be unchanged');
		$this->assertSame(3600, $new->maxTokenLifetimeSeconds);
	}

	public function testWithMaxTokenLifetimeSecondsCanClearToNull(): void {
		$new = $this->makeConfig()->withMaxTokenLifetimeSeconds(3600)->withMaxTokenLifetimeSeconds(null);

		$this->assertNull($new->maxTokenLifetimeSeconds);
	}

	public function testWithAllowUntrustedAudiences(): void {
		$config = $this->makeConfig();
		$new    = $config->withAllowUntrustedAudiences(true);

		$this->assertFalse($config->allowUntrustedAudiences, 'original must be unchanged');
		$this->assertTrue($new->allowUntrustedAudiences);
	}

	public function testWithAllowAnyHost(): void {
		$config = $this->makeConfig();
		$new    = $config->withAllowAnyHost(true);

		$this->assertFalse($config->allowAnyHost, 'original must be unchanged');
		$this->assertTrue($new->allowAnyHost);
	}

	public function testWithClientAuthMethod(): void {
		$config = $this->makeConfig();
		$new    = $config->withClientAuthMethod(ClientAuthMethod::Post);

		$this->assertSame(ClientAuthMethod::Basic, $config->clientAuthMethod, 'original must be unchanged');
		$this->assertSame(ClientAuthMethod::Post, $new->clientAuthMethod);
	}

}
