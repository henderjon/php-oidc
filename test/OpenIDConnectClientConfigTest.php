<?php

namespace Oidc;

use PHPUnit\Framework\TestCase;

class OpenIDConnectClientConfigTest extends TestCase {

	private function makeConfig(): OpenIDConnectClientConfig {
		return new OpenIDConnectClientConfig(
			clientId: 'client-id',
			clientSecret: 'client-secret',
			redirectUri: 'https://example.com/callback',
		);
	}

	public function testConstructorDefaults(): void {
		$config = $this->makeConfig();

		$this->assertSame('client-id', $config->clientId);
		$this->assertSame('client-secret', $config->clientSecret);
		$this->assertSame('https://example.com/callback', $config->redirectUri);
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

	public function testWithRedirectUri(): void {
		$new = $this->makeConfig()->withRedirectUri('https://example.com/other');

		$this->assertSame('https://example.com/other', $new->redirectUri);
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

	/**
	 * Every `with*()` test above only asserts its own field changed - none of them would catch
	 * two adjacent constructor arguments getting silently swapped, since a swap between two
	 * still-default field values looks identical either way. This builds a config with every
	 * field set to a distinct, non-default value, calls every wither once, and asserts every
	 * OTHER field survived that call completely unchanged - the one place an argument landing
	 * in the wrong constructor slot would actually be caught.
	 *
	 * One gap this cannot close: there are three `bool` fields but only two possible values, so
	 * by pigeonhole at least one same-type pair must share a value below, and a swap between
	 * exactly that pair would go undetected. `allowUntrustedAudiences`/`allowAnyHost` - adjacent
	 * constructor parameters, and so the pair a real merge-conflict resolution could plausibly
	 * swap - are deliberately given different values (`true`/`false`) to guarantee that swap is
	 * caught. `allowInsecureSchemes` is left colliding with `allowUntrustedAudiences` (both
	 * `true`) instead: it sits four parameters away from both other bools, separated by three
	 * non-bool parameters, so a hand-resolved conflict swapping it with either while leaving
	 * everything between correctly ordered is not a realistic failure mode the way an adjacent
	 * swap is.
	 */
	public function testWithersOnlyChangeTheirOwnField(): void {
		$config = new OpenIDConnectClientConfig(
			clientId: 'the-client-id',
			clientSecret: 'the-client-secret',
			redirectUri: 'https://example.com/callback',
			issuer: 'https://issuer.example.com',
			scopes: [ 'profile' ],
			audience: 'the-audience',
			endpointOverrides: [ 'token_endpoint' => 'https://issuer.example.com/token' ],
			extraAuthParams: [ 'prompt' => 'consent' ],
			pkce: PkceMode::Required,
			allowInsecureSchemes: true,
			allowedHosts: [ 'issuer.example.com' ],
			allowedAlgorithms: [ 'ES256' ],
			maxTokenLifetimeSeconds: 3600,
			allowUntrustedAudiences: true,
			allowAnyHost: false,
			clientAuthMethod: ClientAuthMethod::Post,
		);

		$this->assertUnchangedExcept($config, $config->withClientId('other-id'), 'clientId');
		$this->assertUnchangedExcept($config, $config->withClientSecret('other-secret'), 'clientSecret');
		$this->assertUnchangedExcept($config, $config->withRedirectUri('https://example.com/other'), 'redirectUri');
		$this->assertUnchangedExcept($config, $config->withIssuer('https://other-issuer.example.com'), 'issuer');
		$this->assertUnchangedExcept($config, $config->withScopes([ 'email' ]), 'scopes');
		$this->assertUnchangedExcept($config, $config->withAudience('other-audience'), 'audience');
		$this->assertUnchangedExcept($config, $config->withEndpointOverrides([ 'jwks_uri' => 'https://issuer.example.com/jwks' ]), 'endpointOverrides');
		$this->assertUnchangedExcept($config, $config->withExtraAuthParams([ 'response_mode' => 'form_post' ]), 'extraAuthParams');
		$this->assertUnchangedExcept($config, $config->withPkce(PkceMode::Optional), 'pkce');
		$this->assertUnchangedExcept($config, $config->withAllowInsecureSchemes(false), 'allowInsecureSchemes');
		$this->assertUnchangedExcept($config, $config->withAllowedHosts([ 'other.example.com' ]), 'allowedHosts');
		$this->assertUnchangedExcept($config, $config->withAllowedAlgorithms([ 'RS256' ]), 'allowedAlgorithms');
		$this->assertUnchangedExcept($config, $config->withMaxTokenLifetimeSeconds(7200), 'maxTokenLifetimeSeconds');
		$this->assertUnchangedExcept($config, $config->withAllowUntrustedAudiences(false), 'allowUntrustedAudiences');
		$this->assertUnchangedExcept($config, $config->withAllowAnyHost(true), 'allowAnyHost');
		$this->assertUnchangedExcept($config, $config->withClientAuthMethod(ClientAuthMethod::Basic), 'clientAuthMethod');
	}

	/**
	 * testWithersOnlyChangeTheirOwnField() above calls every wither by name in a fixed,
	 * hand-written sequence - not reflection-driven - so a new `with*()` method added to the
	 * class later would silently get zero coverage from it rather than failing anything. This
	 * counts the class's actual `with*()` methods via reflection and fails loudly if that count
	 * ever drifts from the number this test file was written to cover, as a prompt to update
	 * testWithersOnlyChangeTheirOwnField() (and its sibling single-field `with*()` tests above)
	 * rather than leaving the new method silently untested by either.
	 */
	public function testEveryWitherIsCoveredByTheFieldIsolationTest(): void {
		$witherCount = count(array_filter(
			(new \ReflectionClass(OpenIDConnectClientConfig::class))->getMethods(\ReflectionMethod::IS_PUBLIC),
			static fn ( \ReflectionMethod $method ): bool => str_starts_with($method->getName(), 'with'),
		));

		$this->assertSame(
			16,
			$witherCount,
			'OpenIDConnectClientConfig gained or lost a with*() method - update testWithersOnlyChangeTheirOwnField() to cover it',
		);
	}

	/**
	 * Asserts every constructor field of $actual matches $expected except $changedField, which
	 * is skipped here precisely because the caller already changed it and is asserting that
	 * change separately - or, for testWithersOnlyChangeTheirOwnField(), doesn't need to check
	 * the new value at all, only that nothing else moved.
	 */
	private function assertUnchangedExcept( OpenIDConnectClientConfig $expected, OpenIDConnectClientConfig $actual, string $changedField ): void {
		$fields = [
			'clientId', 'clientSecret', 'redirectUri', 'issuer', 'scopes', 'audience',
			'endpointOverrides', 'extraAuthParams', 'pkce', 'allowInsecureSchemes',
			'allowedHosts', 'allowedAlgorithms', 'maxTokenLifetimeSeconds',
			'allowUntrustedAudiences', 'allowAnyHost', 'clientAuthMethod',
		];

		foreach( $fields as $field ) {
			if( $field === $changedField ) {
				continue;
			}

			$this->assertEquals($expected->$field, $actual->$field, "expected {$field} to be unchanged");
		}
	}

}
