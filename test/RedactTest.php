<?php

namespace Oidc;

use PHPUnit\Framework\TestCase;

class RedactTest extends TestCase {

	public function testPartialReturnsAnEmptyStringUnchanged(): void {
		$this->assertSame('', Redact::partial(''));
	}

	public function testPartialMasksAValueAtExactlyTheFirstTierBoundaryEntirely(): void {
		// length == VISIBLE_CHARS (5) - the whole value, not just the "extra" beyond 5.
		$this->assertSame('*****', Redact::partial('abcde'));
	}

	public function testPartialRevealsTheLastThreeCharactersJustPastTheFirstBoundary(): void {
		// length == VISIBLE_CHARS + 1 (6) - the first length actually inside the second tier.
		$this->assertSame('***def', Redact::partial('abcdef'));
	}

	public function testPartialRevealsTheLastThreeCharactersAtTheSecondTierBoundary(): void {
		// length == VISIBLE_CHARS * 2 (10) - the second tier's own upper edge.
		$this->assertSame('*******hij', Redact::partial('abcdefghij'));
	}

	public function testPartialRevealsTheLastFiveCharactersJustPastTheSecondBoundary(): void {
		// length == VISIBLE_CHARS * 2 + 1 (11) - the first length inside the third tier.
		$this->assertSame('******ghijk', Redact::partial('abcdefghijk'));
	}

	public function testPartialRevealsTheLastFiveCharactersAtTheThirdTierBoundary(): void {
		// length == VISIBLE_CHARS * 3 (15) - exactly where the third and fourth tiers'
		// conditions both say they apply. The third tier wins because it is checked first.
		$this->assertSame('**********klmno', Redact::partial('abcdefghijklmno'));
	}

	public function testPartialRevealsFirstAndLastFiveCharactersJustPastTheThirdBoundary(): void {
		// length == VISIBLE_CHARS * 3 + 1 (16) - the first length inside the fourth tier.
		$this->assertSame('abcde******lmnop', Redact::partial('abcdefghijklmnop'));
	}

	public function testPartialRevealsFirstAndLastFiveCharactersOfALongValue(): void {
		$this->assertSame(
			'abcde****************vwxyz',
			Redact::partial('abcdefghijklmnopqrstuvwxyz'),
		);
	}

	public function testPartialOutputIsAlwaysTheSameLengthAsTheInput(): void {
		foreach( [ 1, 5, 6, 10, 11, 15, 16, 30, 100 ] as $length ) {
			$value = str_repeat('x', $length);

			$this->assertSame($length, strlen(Redact::partial($value)));
		}
	}

}
