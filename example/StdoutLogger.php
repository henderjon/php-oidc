<?php

declare(strict_types=1);

namespace Example;

use Psr\Log\AbstractLogger;
use Stringable;

final class StdoutLogger extends AbstractLogger {

	/**
	 * `$message` is untyped so this loads against psr/log 1.x, 2.x, and 3.x alike.
	 *
	 * @param string|Stringable  $message
	 * @param array<string,mixed> $context
	 */
	public function log($level, $message, array $context = []): void {
		$contextSummary = $context === [] ? '' : ' ' . json_encode($context);
		echo "[{$level}] {$message}{$contextSummary}\n";
	}

}
