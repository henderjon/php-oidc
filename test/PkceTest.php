<?php

namespace Oidc;

use PHPUnit\Framework\TestCase;

class PkceTest extends TestCase {

	public function testGenerateVerifierProducesASpecCompliantLength(): void {
		$verifier = Pkce::generateVerifier();

		$this->assertSame(43, strlen($verifier));
		$this->assertMatchesRegularExpression('/^[A-Za-z0-9\-_]+$/', $verifier);
	}

	public function testGenerateVerifierIsRandomEachCall(): void {
		$this->assertNotSame(Pkce::generateVerifier(), Pkce::generateVerifier());
	}

	public function testChallengeForMatchesTheRfc7636S256TestVector(): void {
		// RFC 7636 Appendix B.1.
		$verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk';

		$this->assertSame('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', Pkce::challengeFor($verifier));
	}

}
