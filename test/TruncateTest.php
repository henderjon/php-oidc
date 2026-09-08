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

}
