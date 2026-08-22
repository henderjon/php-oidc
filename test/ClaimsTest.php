<?php

namespace Henderjon\Oidc;

use PHPUnit\Framework\TestCase;

class ClaimsTest extends TestCase {

	public function testGet(): void {
		$claims = new Claims([ 'sub' => 'user-1' ]);

		$this->assertSame('user-1', $claims->get('sub'));
	}

	public function testGetReturnsDefaultWhenMissing(): void {
		$claims = new Claims([]);

		$this->assertNull($claims->get('sub'));
		$this->assertSame('fallback', $claims->get('sub', 'fallback'));
	}

	public function testHas(): void {
		$claims = new Claims([ 'sub' => 'user-1' ]);

		$this->assertTrue($claims->has('sub'));
		$this->assertFalse($claims->has('missing'));
	}

	public function testAll(): void {
		$data   = [ 'sub' => 'user-1', 'email' => 'user@example.com' ];
		$claims = new Claims($data);

		$this->assertSame($data, $claims->all());
	}

	public function testConstructAcceptsStdClass(): void {
		$decoded = (object)[ 'sub' => 'user-1' ];
		$claims  = new Claims($decoded);

		$this->assertSame('user-1', $claims->get('sub'));
	}

}
