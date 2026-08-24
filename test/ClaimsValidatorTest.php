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
		$validator = new ClaimsValidator($logger);

		try {
			$validator->validateIssuer($this->validClaims(), 'https://other.example.com', 'the-state');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('https://other.example.com', $records[0]['context']['expected']);
		$this->assertSame('https://issuer.example.com', $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testMismatchedAudienceLogsExpectedAndActual(): void {
		$logger    = new ArrayLogger;
		$validator = new ClaimsValidator($logger);
		$claims    = $this->validClaims([ 'aud' => 'someone-elses-client-id' ]);

		try {
			$validator->validateAudience($claims, 'the-client-id', 'the-state');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame([ 'the-client-id' ], $records[0]['context']['expected']);
		$this->assertSame([ 'someone-elses-client-id' ], $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testMismatchedNonceLogsExpectedAndActual(): void {
		$logger    = new ArrayLogger;
		$validator = new ClaimsValidator($logger);
		$claims    = $this->validClaims([ 'nonce' => 'a-different-nonce' ]);

		try {
			$validator->validateNonce($claims, 'the-nonce', 'the-state');
			$this->fail('Expected AuthenticationFailedException to be thrown');
		} catch( AuthenticationFailedException ) {
		}

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('the-nonce', $records[0]['context']['expected']);
		$this->assertSame('a-different-nonce', $records[0]['context']['actual']);
		$this->assertSame('the-state', $records[0]['context']['state']);
	}

	public function testValidClaimsDoNotLogAnything(): void {
		$logger    = new ArrayLogger;
		$validator = new ClaimsValidator($logger);

		$validator->validate($this->validClaims(), 'https://issuer.example.com', 'the-client-id', 'the-nonce');

		$this->assertSame([], $logger->records);
	}

}
