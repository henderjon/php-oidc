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
		// length == VISIBLE_CHARS * 3 + 1 (16) - the first length inside the fourth tier. The
		// mask is a fixed 5 characters, not 6 (length - 2*VISIBLE_CHARS) - it does not scale
		// with the input's own length.
		$this->assertSame('abcde*****lmnop', Redact::partial('abcdefghijklmnop'));
	}

	public function testPartialRevealsFirstAndLastFiveCharactersOfAValueWithinTheFourthTier(): void {
		// 26 characters - still within the fourth tier (<= LONG_VALUE_THRESHOLD, 32) - the mask
		// stays a fixed 5 characters here too, not 16 (length - 2*VISIBLE_CHARS).
		$this->assertSame(
			'abcde*****vwxyz',
			Redact::partial('abcdefghijklmnopqrstuvwxyz'),
		);
	}

	public function testPartialRevealsFirstFiveAndLastFiveAtTheFourthTierBoundary(): void {
		// length == LONG_VALUE_THRESHOLD (32) - the fourth tier's own upper edge, still last
		// VISIBLE_CHARS (5), not yet the wider LONG_VALUE_TRAILING_VISIBLE_CHARS (8).
		$value = 'ABCDE' . str_repeat('.', 22) . 'VWXYZ';
		$this->assertSame(32, strlen($value));

		$this->assertSame('ABCDE*****VWXYZ', Redact::partial($value));
	}

	public function testPartialRevealsFirstFiveAndLastEightJustPastTheFourthBoundary(): void {
		// length == LONG_VALUE_THRESHOLD + 1 (33) - the first length inside the fifth tier,
		// where the trailing reveal widens from VISIBLE_CHARS (5) to
		// LONG_VALUE_TRAILING_VISIBLE_CHARS (8).
		$value = 'ABCDE' . str_repeat('.', 20) . 'STUVWXYZ';
		$this->assertSame(33, strlen($value));

		$this->assertSame('ABCDE*****STUVWXYZ', Redact::partial($value));
	}

	public function testPartialOutputForAMuchLongerValueStillUsesTheFixedFifthTierShape(): void {
		// A value far past the fifth tier's own boundary (a realistic JWT length, say) must not
		// produce a wall of asterisks scaled to it - the output is the same fixed shape as the
		// shortest fifth-tier value.
		$value = 'ABCDE' . str_repeat('.', 112) . 'STUVWXYZ';

		$this->assertSame('ABCDE*****STUVWXYZ', Redact::partial($value));
	}

	public function testPartialOutputIsAlwaysTheSameLengthAsTheInputForTheFirstThreeTiers(): void {
		// Only true up through the third tier (length <= VISIBLE_CHARS * 3) - the fourth and
		// fifth tiers use a fixed-length mask instead, covered by the tests above.
		foreach( [ 1, 5, 6, 10, 11, 15 ] as $length ) {
			$value = str_repeat('x', $length);

			$this->assertSame($length, strlen(Redact::partial($value)));
		}
	}

}
