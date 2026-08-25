<?php

namespace Oidc;

use PHPUnit\Framework\TestCase;

class IncomingAuthorizationResponseTest extends TestCase {

	public function testConstructWithAuthorizationCode(): void {
		$response = new IncomingAuthorizationResponse([
			'code'  => 'the-code',
			'state' => 'the-state',
		]);

		$this->assertSame('the-code', $response->code);
		$this->assertSame('the-state', $response->state);
		$this->assertNull($response->idToken);
		$this->assertNull($response->accessToken);
		$this->assertFalse($response->hasError());
	}

	public function testConstructWithImplicitFlow(): void {
		$response = new IncomingAuthorizationResponse([
			'id_token'     => 'the-id-token',
			'access_token' => 'the-access-token',
			'state'        => 'the-state',
		]);

		$this->assertSame('the-id-token', $response->idToken);
		$this->assertSame('the-access-token', $response->accessToken);
		$this->assertNull($response->code);
	}

	public function testConstructWithError(): void {
		$response = new IncomingAuthorizationResponse([
			'error'             => 'access_denied',
			'error_description' => 'The user denied access',
		]);

		$this->assertTrue($response->hasError());
		$this->assertSame('access_denied', $response->error);
		$this->assertSame('The user denied access', $response->errorDescription);
	}

	public function testConstructWithNoRecognizedKeys(): void {
		$response = new IncomingAuthorizationResponse([]);

		$this->assertNull($response->code);
		$this->assertNull($response->idToken);
		$this->assertNull($response->accessToken);
		$this->assertNull($response->state);
		$this->assertFalse($response->hasError());
	}

	public function testErrorSummaryWithDescription(): void {
		$response = new IncomingAuthorizationResponse([
			'error'             => 'access_denied',
			'error_description' => 'The user denied access',
		]);

		$this->assertSame('access_denied: The user denied access', $response->errorSummary());
	}

	public function testErrorSummaryWithoutDescription(): void {
		$response = new IncomingAuthorizationResponse([ 'error' => 'access_denied' ]);

		$this->assertSame('access_denied', $response->errorSummary());
	}

	public function testErrorSummaryWithNoErrorIsNull(): void {
		$response = new IncomingAuthorizationResponse([]);

		$this->assertNull($response->errorSummary());
	}

	public function testErrorAtTheLengthLimitIsNotTruncated(): void {
		$response = new IncomingAuthorizationResponse([ 'error' => str_repeat('a', 255) ]);

		$this->assertSame(str_repeat('a', 255), $response->error);
	}

	public function testErrorOverTheLengthLimitIsTruncated(): void {
		$response = new IncomingAuthorizationResponse([ 'error' => str_repeat('a', 256) ]);

		$this->assertSame(str_repeat('a', 255) . '...(truncated)', $response->error);
	}

	public function testErrorDescriptionOverTheLengthLimitIsTruncated(): void {
		$response = new IncomingAuthorizationResponse([
			'error'             => 'access_denied',
			'error_description' => str_repeat('a', 300),
		]);

		$this->assertSame(str_repeat('a', 255) . '...(truncated)', $response->errorDescription);
	}

	public function testTruncatedErrorFieldsKeepErrorSummaryBounded(): void {
		$response = new IncomingAuthorizationResponse([
			'error'             => str_repeat('a', 300),
			'error_description' => str_repeat('b', 300),
		]);

		$this->assertSame(
			str_repeat('a', 255) . '...(truncated): ' . str_repeat('b', 255) . '...(truncated)',
			$response->errorSummary(),
		);
	}

}
