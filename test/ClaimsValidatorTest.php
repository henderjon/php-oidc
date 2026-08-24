<?php

namespace Oidc;

use Oidc\Exceptions\AuthenticationFailedException;
use Oidc\Fakes\ArrayLogger;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

class ClaimsValidatorTest extends TestCase {

	/**
	 * @param array<string,mixed> $overrides
	 */
	private function validClaims( array $overrides = [] ): Claims {
		return new Claims([
			'iss'   => 'https://issuer.example.com',
			'aud'   => 'the-client-id',
			'nonce' => 'the-nonce',
			'sub'   => 'the-subject',
			'iat'   => 1_700_000_000,
			'exp'   => 1_700_000_300,
			...$overrides,
		]);
	}

	public function testValidClaimsPass(): void {
		$validator = new ClaimsValidator;

		$validator->validate($this->validClaims(), 'https://issuer.example.com', 'the-client-id', 'the-nonce');

		$this->addToAssertionCount(1);
	}

	public function testMismatchedIssuerFails(): void {
		$validator = new ClaimsValidator;

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('issuer');

		$validator->validate($this->validClaims(), 'https://other.example.com', 'the-client-id', 'the-nonce');
	}

	public function testMatchingAudienceAsArrayPasses(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id', 'other-client' ] ]);

		$validator->validate($claims, 'https://issuer.example.com', 'the-client-id', 'the-nonce');

		$this->addToAssertionCount(1);
	}

	public function testAudienceNotIncludingClientIdFails(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => 'other-client-id' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('audience');

		$validator->validate($claims, 'https://issuer.example.com', 'the-client-id', 'the-nonce');
	}

	public function testMismatchedNonceFails(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'nonce' => 'a-different-nonce' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('nonce');

		$validator->validate($claims, 'https://issuer.example.com', 'the-client-id', 'the-nonce');
	}

	public function testMissingNonceFailsWhenOneWasExpected(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'nonce' => null ]);

		$this->expectException(AuthenticationFailedException::class);

		$validator->validate($claims, 'https://issuer.example.com', 'the-client-id', 'the-nonce');
	}

	public function testNoNonceExpectedSkipsTheCheck(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'nonce' => null ]);

		$validator->validate($claims, 'https://issuer.example.com', 'the-client-id', null);

		$this->addToAssertionCount(1);
	}

	public function testValidateAudienceAcceptsAnyOfSeveralExpectedValues(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => 'the-resource-audience' ]);

		$validator->validateAudience($claims, [ 'the-client-id', 'the-resource-audience' ]);

		$this->addToAssertionCount(1);
	}

	public function testValidateAudienceWithArrayExpectedAndArrayActualPasses(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => [ 'other-client', 'the-resource-audience' ] ]);

		$validator->validateAudience($claims, [ 'the-client-id', 'the-resource-audience' ]);

		$this->addToAssertionCount(1);
	}

	public function testValidateAudienceWithArrayExpectedAndNoOverlapFails(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => 'someone-else' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('audience');

		$validator->validateAudience($claims, [ 'the-client-id', 'the-resource-audience' ]);
	}

	public function testMismatchedIssuerLogsExpectedAndActual(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');

		try {
			$validator->validateIssuer($this->validClaims(), 'https://other.example.com');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('https://other.example.com', $records[0]['context']['expected']);
		$this->assertSame('https://issuer.example.com', $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testMismatchedAudienceLogsExpectedAndActual(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'aud' => 'someone-elses-client-id' ]);

		try {
			$validator->validateAudience($claims, 'the-client-id');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame([ 'the-client-id' ], $records[0]['context']['expected']);
		$this->assertSame([ 'someone-elses-client-id' ], $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testMismatchedNonceLogsExpectedAndActual(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'nonce' => 'a-different-nonce' ]);

		try {
			$validator->validateNonce($claims, 'the-nonce');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('the-nonce', $records[0]['context']['expected']);
		$this->assertSame('a-different-nonce', $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testValidateRequiredClaimsPassesWithAllPresent(): void {
		$validator = new ClaimsValidator;

		$validator->validateRequiredClaims($this->validClaims());

		$this->addToAssertionCount(1);
	}

	public function testValidateRequiredClaimsRejectsMissingSub(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'sub' => null ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('sub');

		$validator->validateRequiredClaims($claims);
	}

	public function testValidateRequiredClaimsRejectsEmptyStringSub(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'sub' => '' ]);

		$this->expectException(AuthenticationFailedException::class);

		$validator->validateRequiredClaims($claims);
	}

	public function testValidateRequiredClaimsRejectsMissingExp(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'exp' => null ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('exp');

		$validator->validateRequiredClaims($claims);
	}

	public function testValidateRequiredClaimsRejectsNonNumericExp(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'exp' => 'not-a-number' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('exp');

		$validator->validateRequiredClaims($claims);
	}

	public function testValidateRequiredClaimsRejectsMissingIat(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'iat' => null ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('iat');

		$validator->validateRequiredClaims($claims);
	}

	public function testValidateRequiredClaimsRejectsNonNumericIat(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'iat' => 'not-a-number' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('iat');

		$validator->validateRequiredClaims($claims);
	}

	public function testValidateRequiredClaimsRejectsExpNotAfterIat(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'iat' => 1_700_000_300, 'exp' => 1_700_000_300 ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('exp');

		$validator->validateRequiredClaims($claims);
	}

	public function testValidateRequiredClaimsRejectsExpBeforeIat(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'iat' => 1_700_000_300, 'exp' => 1_700_000_000 ]);

		$this->expectException(AuthenticationFailedException::class);

		$validator->validateRequiredClaims($claims);
	}

	public function testValidateRequiredClaimsLogsTheMissingSub(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'sub' => null ]);

		try {
			$validator->validateRequiredClaims($claims);
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: ID token is missing the required sub claim', $records[0]['message']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testValidateTokenLifetimeSkipsCheckWhenNull(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'iat' => 0, 'exp' => 999_999_999 ]);

		$validator->validateTokenLifetime($claims, null);

		$this->addToAssertionCount(1);
	}

	public function testValidateTokenLifetimeAllowsALifetimeWithinTheCap(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'iat' => 1_700_000_000, 'exp' => 1_700_000_300 ]);

		$validator->validateTokenLifetime($claims, 600);

		$this->addToAssertionCount(1);
	}

	public function testValidateTokenLifetimeRejectsALifetimeOverTheCap(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'iat' => 1_700_000_000, 'exp' => 1_700_001_000 ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('lifetime');

		$validator->validateTokenLifetime($claims, 600);
	}

	public function testValidateTokenLifetimeLogsTheLifetimeAndCap(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'iat' => 1_700_000_000, 'exp' => 1_700_001_000 ]);

		try {
			$validator->validateTokenLifetime($claims, 600);
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame(1000.0, $records[0]['context']['lifetime_seconds']);
		$this->assertSame(600, $records[0]['context']['max_lifetime_seconds']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testValidClaimsDoNotLogAnything(): void {
		$logger    = new ArrayLogger;
		$validator = new ClaimsValidator($logger);

		$validator->validate($this->validClaims(), 'https://issuer.example.com', 'the-client-id', 'the-nonce');

		$this->assertSame([], $logger->records);
	}

	public function testWithStateDoesNotAffectTheOriginalInstance(): void {
		$logger    = new ArrayLogger;
		$validator = new ClaimsValidator($logger);

		$validator->withState('the-state');

		try {
			$validator->validateIssuer($this->validClaims(), 'https://other.example.com');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$this->assertNull($logger->recordsAt(LogLevel::ERROR)[0]['context']['state']);
	}

}
