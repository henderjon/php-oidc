<?php

namespace Oidc;

use Oidc\Fakes\ArrayLogger;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

class LogLevelFilterLoggerTest extends TestCase {

	public function testForwardsAnAllowedLevel(): void {
		$inner = new ArrayLogger;
		$logger = new LogLevelFilterLogger($inner, [ LogLevel::DEBUG ]);

		$logger->debug('a debug message', [ 'key' => 'value' ]);

		$this->assertCount(1, $inner->records);
		$this->assertSame(LogLevel::DEBUG, $inner->records[0]['level']);
		$this->assertSame('a debug message', $inner->records[0]['message']);
		$this->assertSame([ 'key' => 'value' ], $inner->records[0]['context']);
	}

	public function testDropsALevelNotInTheAllowlist(): void {
		$inner  = new ArrayLogger;
		$logger = new LogLevelFilterLogger($inner, [ LogLevel::DEBUG ]);

		$logger->error('an error message');

		$this->assertSame([], $inner->records);
	}

	public function testAllowsMultipleLevelsAtOnce(): void {
		$inner  = new ArrayLogger;
		$logger = new LogLevelFilterLogger($inner, [ LogLevel::DEBUG, LogLevel::CRITICAL ]);

		$logger->debug('a debug message');
		$logger->warning('a warning message');
		$logger->error('an error message');
		$logger->critical('a critical message');

		$this->assertCount(2, $inner->records);
		$this->assertSame(LogLevel::DEBUG, $inner->records[0]['level']);
		$this->assertSame(LogLevel::CRITICAL, $inner->records[1]['level']);
	}

	public function testAnEmptyAllowlistDropsEverything(): void {
		$inner  = new ArrayLogger;
		$logger = new LogLevelFilterLogger($inner, []);

		$logger->emergency('an emergency message');
		$logger->debug('a debug message');

		$this->assertSame([], $inner->records);
	}

	public function testEveryPsr3LevelMethodDelegatesThroughLog(): void {
		// LoggerTrait (via AbstractLogger) implements each level-specific method by calling
		// log() with that level - this proves the allowlist actually governs all eight, not
		// just the generic log() call sites exercised above.
		$inner  = new ArrayLogger;
		$logger = new LogLevelFilterLogger($inner, [
			LogLevel::EMERGENCY, LogLevel::ALERT, LogLevel::CRITICAL, LogLevel::ERROR,
			LogLevel::WARNING, LogLevel::NOTICE, LogLevel::INFO, LogLevel::DEBUG,
		]);

		$logger->emergency('m');
		$logger->alert('m');
		$logger->critical('m');
		$logger->error('m');
		$logger->warning('m');
		$logger->notice('m');
		$logger->info('m');
		$logger->debug('m');

		$this->assertSame(
			[ LogLevel::EMERGENCY, LogLevel::ALERT, LogLevel::CRITICAL, LogLevel::ERROR, LogLevel::WARNING, LogLevel::NOTICE, LogLevel::INFO, LogLevel::DEBUG ],
			array_column($inner->records, 'level'),
		);
	}

	public function testDefaultContextIsAnEmptyArray(): void {
		$inner  = new ArrayLogger;
		$logger = new LogLevelFilterLogger($inner, [ LogLevel::DEBUG ]);

		$logger->debug('a debug message');

		$this->assertSame([], $inner->records[0]['context']);
	}

	public function testAllForwardsEveryStandardLevel(): void {
		$inner  = new ArrayLogger;
		$logger = LogLevelFilterLogger::all($inner);

		$logger->emergency('m');
		$logger->debug('m');

		$this->assertCount(2, $inner->records);
	}

	public function testAllForwardsALevelPsr3DoesNotDefine(): void {
		// PSR-3 never restricts $level to its own eight constants - a caller with its own
		// custom level would be silently dropped by any allowlist that only enumerates
		// Psr\Log\LogLevel's constants by hand. all() exists for exactly this case.
		$inner  = new ArrayLogger;
		$logger = LogLevelFilterLogger::all($inner);

		$logger->log('a-custom-non-psr3-level', 'm');

		$this->assertCount(1, $inner->records);
		$this->assertSame('a-custom-non-psr3-level', $inner->records[0]['level']);
	}

	public function testIncludeFalseTreatsLevelsAsADenylistDroppingTheNamedLevel(): void {
		$inner  = new ArrayLogger;
		$logger = new LogLevelFilterLogger($inner, [ LogLevel::DEBUG ], include: false);

		$logger->debug('a debug message');

		$this->assertSame([], $inner->records);
	}

	public function testIncludeFalseForwardsEveryOtherStandardLevel(): void {
		$inner  = new ArrayLogger;
		$logger = new LogLevelFilterLogger($inner, [ LogLevel::DEBUG ], include: false);

		$logger->emergency('m');
		$logger->alert('m');
		$logger->critical('m');
		$logger->error('m');
		$logger->warning('m');
		$logger->notice('m');
		$logger->info('m');

		$this->assertCount(7, $inner->records);
	}

	public function testIncludeFalseForwardsALevelPsr3DoesNotDefine(): void {
		// A level nobody named - including a custom one neither PSR-3 nor $levels knows about
		// - is exactly what a deny-list forwards by design, unlike the default allow-list,
		// which would drop it.
		$inner  = new ArrayLogger;
		$logger = new LogLevelFilterLogger($inner, [ LogLevel::DEBUG ], include: false);

		$logger->log('a-custom-non-psr3-level', 'm');

		$this->assertCount(1, $inner->records);
		$this->assertSame('a-custom-non-psr3-level', $inner->records[0]['level']);
	}

	public function testIncludeFalseCanExcludeMultipleLevelsAtOnce(): void {
		$inner  = new ArrayLogger;
		$logger = new LogLevelFilterLogger($inner, [ LogLevel::DEBUG, LogLevel::INFO ], include: false);

		$logger->debug('m');
		$logger->info('m');
		$logger->warning('m');

		$this->assertCount(1, $inner->records);
		$this->assertSame(LogLevel::WARNING, $inner->records[0]['level']);
	}

	public function testAllIsEquivalentToAnEmptyDenylist(): void {
		// all()'s own docblock calls it sugar for an empty deny-list - proves that directly.
		$inner  = new ArrayLogger;
		$logger = new LogLevelFilterLogger($inner, [], include: false);

		$logger->emergency('m');
		$logger->debug('m');
		$logger->log('a-custom-non-psr3-level', 'm');

		$this->assertCount(3, $inner->records);
	}

}
