<?php

namespace Oidc;

use PHPUnit\Framework\TestCase;

class RedactTest extends TestCase {

	public function testPartialRevealsTheFirstAndLastFiveCharactersOfALongValue(): void {
		$this->assertSame('abcde...vwxyz', Redact::partial('abcdefghijklmnopqrstuvwxyz'));
	}

	public function testPartialMasksAValueShortEnoughThatBothEndsWouldOverlap(): void {
		$this->assertSame('*********', Redact::partial('123456789'));
	}

	public function testPartialMasksAValueExactlyTenCharactersLongEntirely(): void {
		// Ten characters is exactly two non-overlapping five-character halves - still masked
		// outright, since revealing both halves of a ten-character secret is revealing all of it.
		$this->assertSame('**********', Redact::partial('1234567890'));
	}

	public function testPartialRevealsAnElevenCharacterValue(): void {
		// One character past the masking boundary - the first real case where "first five,
		// last five" leaves something actually hidden in the middle.
		$this->assertSame('12345...78901', Redact::partial('12345678901'));
	}

	public function testPartialReturnsAnEmptyStringUnchanged(): void {
		$this->assertSame('', Redact::partial(''));
	}

}
