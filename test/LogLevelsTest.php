<?php

namespace Oidc;

use PHPUnit\Framework\TestCase;

class LogLevelsTest extends TestCase {

	public function testAllIsNotOneOfPsr3sOwnEightLevels(): void {
		$psr3Levels = [
			\Psr\Log\LogLevel::EMERGENCY,
			\Psr\Log\LogLevel::ALERT,
			\Psr\Log\LogLevel::CRITICAL,
			\Psr\Log\LogLevel::ERROR,
			\Psr\Log\LogLevel::WARNING,
			\Psr\Log\LogLevel::NOTICE,
			\Psr\Log\LogLevel::INFO,
			\Psr\Log\LogLevel::DEBUG,
		];

		$this->assertNotContains(LogLevels::ALL, $psr3Levels);
	}

}
