<?php

namespace Oidc\Fakes;

use Firebase\JWT\JWT;
use PHPUnit\Framework\TestCase;

class EcKeyFixtureTest extends TestCase {

	public function testFixedWidthCoordinatePadsAShortCoordinateWithLeadingZeros(): void {
		$short = str_repeat("\x01", 31);

		$padded = EcKeyFixture::fixedWidthCoordinate($short);

		$this->assertSame(32, strlen($padded));
		$this->assertSame("\x00" . $short, $padded);
	}

	public function testFixedWidthCoordinateLeavesAFullWidthCoordinateUnchanged(): void {
		$fullWidth = str_repeat("\x01", 32);

		$this->assertSame($fullWidth, EcKeyFixture::fixedWidthCoordinate($fullWidth));
	}

	/**
	 * openssl_pkey_get_details() returns EC coordinates as minimal-length big-endian
	 * integers, not fixed-width - roughly 1 in 256 generated keys has a coordinate one byte
	 * shorter than P-256's 32-byte width. The two unit tests above cover
	 * fixedWidthCoordinate() deterministically; this loop is a cheaper, real end-to-end
	 * check that the constructor actually applies it to both x and y, not just one.
	 */
	public function testGeneratedKeysAlwaysProduceFixedWidthCoordinates(): void {
		for( $i = 0; $i < 100; $i++ ) {
			$jwks = (new EcKeyFixture)->jwks();

			$x = JWT::urlsafeB64Decode($jwks['keys'][0]['x']);
			$y = JWT::urlsafeB64Decode($jwks['keys'][0]['y']);

			$this->assertSame(32, strlen($x), "x was not 32 bytes on iteration {$i}");
			$this->assertSame(32, strlen($y), "y was not 32 bytes on iteration {$i}");
		}
	}

}
