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

	public function testMismatchedIssuerCarriesTheScopedStateOnTheException(): void {
		$validator = (new ClaimsValidator)->withState('the-flow-state');

		try {
			$validator->validate($this->validClaims(), 'https://other.example.com', 'the-client-id', 'the-nonce');
			$this->fail('Expected an AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			$this->assertSame('the-flow-state', $e->getState());
		}
	}

	public function testAFailureWithNoScopedStateCarriesNullOnTheException(): void {
		$validator = new ClaimsValidator;

		try {
			$validator->validate($this->validClaims(), 'https://other.example.com', 'the-client-id', 'the-nonce');
			$this->fail('Expected an AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException $e ) {
			$this->assertNull($e->getState());
		}
	}

	public function testMatchingAudienceAsArrayPasses(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id' ] ]);

		$validator->validate($claims, 'https://issuer.example.com', 'the-client-id', 'the-nonce');

		$this->addToAssertionCount(1);
	}

	public function testAudienceContainingAnUntrustedExtraValueFails(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id', 'an-untrusted-audience' ] ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('not trusted');

		$validator->validate($claims, 'https://issuer.example.com', 'the-client-id', 'the-nonce');
	}

	public function testAllowUntrustedAudiencesOptsOutOfTheExtraValueCheck(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id', 'an-untrusted-audience' ] ]);

		$validator->validateAudience($claims, 'the-client-id', allowUntrustedAudiences: true);

		$this->addToAssertionCount(1);
	}

	public function testAllowUntrustedAudiencesStillRequiresTheExpectedValueToBePresent(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => [ 'someone-elses-client-id', 'an-untrusted-audience' ] ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('does not match any of the expected values');

		$validator->validateAudience($claims, 'the-client-id', allowUntrustedAudiences: true);
	}

	public function testAllowUntrustedAudiencesLogsAnAlertWhenItActuallyLetsSomethingThrough(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id', 'an-untrusted-audience' ] ]);

		$validator->validateAudience($claims, 'the-client-id', allowUntrustedAudiences: true);

		$records = $logger->recordsAt(LogLevel::ALERT);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: ID token audience contains untrusted values, allowed through by configuration', $records[0]['message']);
		$this->assertSame([ 'the-client-id' ], $records[0]['context']['expected']);
		$this->assertSame([ 'the-client-id', 'an-untrusted-audience' ], $records[0]['context']['actual']);
		$this->assertSame([ 'an-untrusted-audience' ], $records[0]['context']['untrusted']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testAllowUntrustedAudiencesDoesNotLogWhenThereIsNothingToBypass(): void {
		$logger    = new ArrayLogger;
		$validator = new ClaimsValidator($logger);
		$claims    = $this->validClaims([ 'aud' => 'the-client-id' ]);

		$validator->validateAudience($claims, 'the-client-id', allowUntrustedAudiences: true);

		$this->assertSame([], $logger->records);
	}

	public function testMalformedAudienceEntryFailsByDefault(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id', 42 ] ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('malformed');

		$validator->validateAudience($claims, 'the-client-id');
	}

	public function testMalformedAudienceEntryLogsTheRawClaimAndTheMalformedValues(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id', 42, null ] ]);

		try {
			$validator->validateAudience($claims, 'the-client-id');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: ID token audience contains a malformed value', $records[0]['message']);
		$this->assertSame([ 'the-client-id', 42, null ], $records[0]['context']['aud']);
		$this->assertSame([ 42, null ], $records[0]['context']['malformed']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testAllowUntrustedAudiencesRelaxesTheMalformedEntryCheck(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id', 42 ] ]);

		$validator->validateAudience($claims, 'the-client-id', allowUntrustedAudiences: true);

		$this->addToAssertionCount(1);
	}

	public function testANonArrayNonStringAudienceIsNotTreatedAsMalformed(): void {
		// Already handled correctly without this check: a bare wrong-typed aud normalizes to
		// an empty actual list and fails the ordinary "does not match" check on its own - a
		// distinct "malformed" error is not needed for this shape.
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => 42 ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('does not match any of the expected values');

		$validator->validateAudience($claims, 'the-client-id');
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
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id', 'the-resource-audience' ] ]);

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
		// An issuer mismatch is usually a misconfigured client, not an attack - it stays
		// outside the small curated set of error() calls marked security_relevant: true.
		$this->assertFalse($records[0]['context']['security_relevant']);
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

	public function testUntrustedExtraAudienceLogsTheUntrustedValues(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id', 'an-untrusted-audience' ] ]);

		try {
			$validator->validateAudience($claims, 'the-client-id');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: ID token audience contains additional values not trusted by this client', $records[0]['message']);
		// The full expected and actual sets are logged, not just the offending value(s) -
		// debugging a rejection should never require separately reconstructing what the
		// token actually claimed or what this call expected.
		$this->assertSame([ 'the-client-id' ], $records[0]['context']['expected']);
		$this->assertSame([ 'the-client-id', 'an-untrusted-audience' ], $records[0]['context']['actual']);
		$this->assertSame([ 'an-untrusted-audience' ], $records[0]['context']['untrusted']);
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
		// A returned nonce that does not match the one this client generated is essentially
		// unexplainable except as a replay or injection attempt - one of the small set of
		// error() calls marked security_relevant: true.
		$this->assertTrue($records[0]['context']['security_relevant']);
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

	public function testValidateRequiredClaimsAllowsSubAtTheLengthLimit(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'sub' => str_repeat('a', 255) ]);

		$validator->validateRequiredClaims($claims);

		$this->addToAssertionCount(1);
	}

	public function testValidateRequiredClaimsRejectsSubOverTheLengthLimit(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'sub' => str_repeat('a', 256) ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('exceeds the maximum allowed length');

		$validator->validateRequiredClaims($claims);
	}

	public function testValidateRequiredClaimsLogsTheOversizedSubLength(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'sub' => str_repeat('a', 256) ]);

		try {
			$validator->validateRequiredClaims($claims);
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: ID token sub claim exceeds the maximum allowed length', $records[0]['message']);
		$this->assertSame(256, $records[0]['context']['length']);
		$this->assertSame(255, $records[0]['context']['max']);
		$this->assertSame('the-state', $records[0]['context']['state']);
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

	public function testValidateUserInfoSubjectPassesWhenItMatches(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'sub' => 'the-subject' ]);

		$validator->validateUserInfoSubject($claims, 'the-subject');

		$this->addToAssertionCount(1);
	}

	public function testValidateUserInfoSubjectFailsWhenMissing(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'sub' => null ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('missing');

		$validator->validateUserInfoSubject($claims, 'the-subject');
	}

	public function testValidateUserInfoSubjectFailsWhenEmptyString(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'sub' => '' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('missing');

		$validator->validateUserInfoSubject($claims, 'the-subject');
	}

	public function testValidateUserInfoSubjectFailsWhenItDoesNotMatch(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'sub' => 'someone-elses-subject' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('does not match the authenticated ID token subject');

		$validator->validateUserInfoSubject($claims, 'the-subject');
	}

	public function testValidateUserInfoSubjectLogsExpectedAndActualOnMismatch(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'sub' => 'someone-elses-subject' ]);

		try {
			$validator->validateUserInfoSubject($claims, 'the-subject');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('the-subject', $records[0]['context']['expected']);
		$this->assertSame('someone-elses-subject', $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testValidateUserInfoSubjectLogsOnMissing(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'sub' => null ]);

		try {
			$validator->validateUserInfoSubject($claims, 'the-subject');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: UserInfo response is missing the required sub claim', $records[0]['message']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testValidateUserInfoIssuerPassesWhenItMatches(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'iss' => 'https://issuer.example.com' ]);

		$validator->validateUserInfoIssuer($claims, 'https://issuer.example.com');

		$this->addToAssertionCount(1);
	}

	public function testValidateUserInfoIssuerFailsWhenItDoesNotMatch(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'iss' => 'https://other.example.com' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('UserInfo response issuer');

		$validator->validateUserInfoIssuer($claims, 'https://issuer.example.com');
	}

	public function testValidateUserInfoIssuerLogsExpectedAndActual(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'iss' => 'https://other.example.com' ]);

		try {
			$validator->validateUserInfoIssuer($claims, 'https://issuer.example.com');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('https://issuer.example.com', $records[0]['context']['expected']);
		$this->assertSame('https://other.example.com', $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testValidateUserInfoAudiencePassesWhenClientIdIsIncluded(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id', 'some-other-resource' ] ]);

		$validator->validateUserInfoAudience($claims, 'the-client-id');

		$this->addToAssertionCount(1);
	}

	public function testValidateUserInfoAudiencePassesWithASingleStringAudience(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => 'the-client-id' ]);

		$validator->validateUserInfoAudience($claims, 'the-client-id');

		$this->addToAssertionCount(1);
	}

	public function testValidateUserInfoAudienceDoesNotRejectUntrustedExtraValues(): void {
		// Unlike the ID token's validateAudience(), §5.3.2 places no "no untrusted extra
		// audiences" requirement on the UserInfo response - an extra value alongside the
		// client id must not fail this check.
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => [ 'the-client-id', 'an-extra-audience' ] ]);

		$validator->validateUserInfoAudience($claims, 'the-client-id');

		$this->addToAssertionCount(1);
	}

	public function testValidateUserInfoAudienceFailsWhenClientIdIsNotIncluded(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'aud' => 'someone-elses-client-id' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('UserInfo response audience');

		$validator->validateUserInfoAudience($claims, 'the-client-id');
	}

	public function testValidateUserInfoAudienceLogsExpectedAndActual(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'aud' => 'someone-elses-client-id' ]);

		try {
			$validator->validateUserInfoAudience($claims, 'the-client-id');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('the-client-id', $records[0]['context']['expected']);
		$this->assertSame([ 'someone-elses-client-id' ], $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testValidateRefreshedSubjectPassesWhenItMatches(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'sub' => 'the-subject' ]);

		$validator->validateRefreshedSubject($claims, 'the-subject');

		$this->addToAssertionCount(1);
	}

	public function testValidateRefreshedSubjectFailsWhenItDoesNotMatch(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'sub' => 'someone-elses-subject' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('does not match the original ID token');

		$validator->validateRefreshedSubject($claims, 'the-subject');
	}

	public function testValidateRefreshedSubjectLogsExpectedAndActual(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'sub' => 'someone-elses-subject' ]);

		try {
			$validator->validateRefreshedSubject($claims, 'the-subject');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('the-subject', $records[0]['context']['expected']);
		$this->assertSame('someone-elses-subject', $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testValidateRefreshedAuthTimeSkipsCheckWhenNotPresent(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims();

		$validator->validateRefreshedAuthTime($claims, null);

		$this->addToAssertionCount(1);
	}

	public function testValidateRefreshedAuthTimePassesWhenItMatchesTheOriginal(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'auth_time' => 1_700_000_000 ]);

		$validator->validateRefreshedAuthTime($claims, 1_700_000_000);

		$this->addToAssertionCount(1);
	}

	public function testValidateRefreshedAuthTimeFailsWhenItDoesNotMatchTheOriginal(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'auth_time' => 1_700_000_300 ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('does not match the original authentication time');

		$validator->validateRefreshedAuthTime($claims, 1_700_000_000);
	}

	public function testValidateRefreshedAuthTimeFailsWhenTheOriginalNeverHadOne(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'auth_time' => 1_700_000_000 ]);

		$this->expectException(AuthenticationFailedException::class);

		$validator->validateRefreshedAuthTime($claims, null);
	}

	public function testValidateRefreshedAuthTimeLogsExpectedAndActual(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'auth_time' => 1_700_000_300 ]);

		try {
			$validator->validateRefreshedAuthTime($claims, 1_700_000_000);
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame(1_700_000_000, $records[0]['context']['expected']);
		$this->assertSame(1_700_000_300, $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testValidateRefreshedNonceSkipsCheckWhenNotPresent(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'nonce' => null ]);

		$validator->validateRefreshedNonce($claims, null);

		$this->addToAssertionCount(1);
	}

	public function testValidateRefreshedNoncePassesWhenItMatchesTheOriginal(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'nonce' => 'the-nonce' ]);

		$validator->validateRefreshedNonce($claims, 'the-nonce');

		$this->addToAssertionCount(1);
	}

	public function testValidateRefreshedNonceFailsWhenItDoesNotMatchTheOriginal(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'nonce' => 'a-different-nonce' ]);

		$this->expectException(AuthenticationFailedException::class);
		$this->expectExceptionMessage('does not match the original ID token');

		$validator->validateRefreshedNonce($claims, 'the-nonce');
	}

	public function testValidateRefreshedNonceFailsWhenTheOriginalHadNone(): void {
		$validator = new ClaimsValidator;
		$claims    = $this->validClaims([ 'nonce' => 'a-nonce' ]);

		$this->expectException(AuthenticationFailedException::class);

		$validator->validateRefreshedNonce($claims, null);
	}

	public function testValidateRefreshedNonceLogsExpectedAndActual(): void {
		$logger    = new ArrayLogger;
		$validator = (new ClaimsValidator($logger))->withState('the-state');
		$claims    = $this->validClaims([ 'nonce' => 'a-different-nonce' ]);

		try {
			$validator->validateRefreshedNonce($claims, 'the-nonce');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('the-nonce', $records[0]['context']['expected']);
		$this->assertSame('a-different-nonce', $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
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
