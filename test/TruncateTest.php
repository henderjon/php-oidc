<?php

namespace Oidc;

use PHPUnit\Framework\TestCase;

class TruncateTest extends TestCase {

	public function testLeavesAValueAtOrUnderTheLimitUnchanged(): void {
		$this->assertSame('abcde', Truncate::to('abcde', 5));
	}

	public function testLeavesAnEmptyStringUnchanged(): void {
		$this->assertSame('', Truncate::to('', 5));
	}

	public function testLeavesAMultibyteValueAtTheCharacterLimitUnchanged(): void {
		$this->assertSame('abcdé', Truncate::to('abcdé', 5));
	}

	public function testCutsAValueOverTheLimitAndAppendsATruncatedMarker(): void {
		$this->assertSame('abcde...(truncated)', Truncate::to('abcdefghij', 5));
	}

	public function testTheCutPortionIsExactlyTheMaxLength(): void {
		$value = str_repeat('x', 100);

		$this->assertSame(str_repeat('x', 10) . '...(truncated)', Truncate::to($value, 10));
	}

	public function testAZeroMaxLengthTruncatesAnyNonEmptyValueToJustTheMarker(): void {
		$this->assertSame('...(truncated)', Truncate::to('a', 0));
	}

	public function testANegativeMaxLengthIsClampedToZeroRatherThanTriggeringSubstrsOwnMeaning(): void {
		// Without the clamp, substr('abcdef', 0, -2) would mean "all but the last 2
		// characters" ('abcd'), not "no characters" - the opposite of what a negative max
		// length should mean here.
		$this->assertSame('...(truncated)', Truncate::to('abcdef', -2));
	}

	public function testANegativeMaxLengthStillLeavesAnEmptyValueUnchanged(): void {
		$this->assertSame('', Truncate::to('', -2));
	}

	public function testNeverSplitsAMultiByteCharacterAtTheCutPoint(): void {
		// A 2-byte UTF-8 character ("é") straddling the byte-64 cutoff, confirmed to actually
		// produce invalid UTF-8 (and break json_encode() for the whole log record it is
		// embedded in) when cut with a byte-oblivious substr() instead - see this class's own
		// docblock.
		$value  = str_repeat('a', 63) . 'é' . str_repeat('b', 10);
		$result = Truncate::to($value, 64);

		$this->assertSame(str_repeat('a', 63) . '...(truncated)', $result);
		$this->assertTrue(mb_check_encoding($result, 'UTF-8'));
		$this->assertNotFalse(json_encode([ 'k' => $result ]));
	}

}
