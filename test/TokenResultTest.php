<?php

namespace Oidc;

use Oidc\Exceptions\TokenRequestException;
use Oidc\Fakes\ArrayLogger;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

class TokenResultTest extends TestCase {

	public function testConstructWithFullResponse(): void {
		$result = new TokenResult([
			'access_token'  => 'the-access-token',
			'token_type'    => 'Bearer',
			'expires_in'    => 3600,
			'refresh_token' => 'the-refresh-token',
			'id_token'      => 'the-id-token',
			'scope'         => 'openid email',
		]);

		$this->assertSame('the-access-token', $result->accessToken);
		$this->assertSame('Bearer', $result->tokenType);
		$this->assertSame(3600, $result->expiresIn);
		$this->assertSame('the-refresh-token', $result->refreshToken);
		$this->assertSame('the-id-token', $result->idToken);
		$this->assertSame('openid email', $result->scope);
	}

	public function testConstructDefaultsTokenTypeToBearer(): void {
		$result = new TokenResult([ 'access_token' => 'the-access-token' ]);

		$this->assertSame('Bearer', $result->tokenType);
		$this->assertNull($result->expiresIn);
		$this->assertNull($result->refreshToken);
		$this->assertNull($result->idToken);
		$this->assertNull($result->scope);
	}

	public function testConstructThrowsWhenAccessTokenMissing(): void {
		$this->expectException(TokenRequestException::class);

		new TokenResult([ 'token_type' => 'Bearer' ]);
	}

	public function testConstructThrowsWhenAccessTokenEmpty(): void {
		$this->expectException(TokenRequestException::class);

		new TokenResult([ 'access_token' => '' ]);
	}

	public function testConstructCarriesTheGivenStateOnTheException(): void {
		try {
			new TokenResult([ 'access_token' => '' ], state: 'the-flow-state');
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException $e ) {
			$this->assertSame('the-flow-state', $e->getState());
		}
	}

	public function testLogsInvalidResponseFieldNamesAndTheirActualValues(): void {
		$logger = new ArrayLogger;

		try {
			new TokenResult([
				'access_token' => '',
				'expires_in'   => '3600',
			], $logger, 'the-state');
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame([ 'access_token', 'expires_in' ], $records[0]['context']['invalid_fields']);
		$this->assertSame(
			[ 'access_token' => '', 'expires_in' => '3600' ],
			$records[0]['context']['invalid_field_values'],
		);
		$this->assertSame('the-state', $records[0]['context']['state']);
		// A malformed token response is an ordinary shape failure, not one of the curated
		// high-confidence attack indicators - security_relevant stays false.
		$this->assertFalse($records[0]['context']['security_relevant']);
	}

	public function testLogsNullAsTheValueForAnEntirelyMissingAccessToken(): void {
		$logger = new ArrayLogger;

		try {
			new TokenResult([ 'token_type' => 'Bearer' ], $logger);
			$this->fail('Expected a TokenRequestException to be thrown');
		} catch( TokenRequestException ) {
		}

		$this->assertNull($logger->recordsAt(LogLevel::ERROR)[0]['context']['invalid_field_values']['access_token']);
	}

	public function testLogsTheActualMalformedValueForANonStringField(): void {
		$logger = new ArrayLogger;

		new TokenResult([
			'access_token' => 'the-access-token',
			'scope'        => [ 'read', 'write' ],
		], $logger);

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertSame([ 'read', 'write' ], $records[0]['context']['invalid_field_values']['scope']);
	}

}
