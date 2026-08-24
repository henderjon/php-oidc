<?php

declare(strict_types=1);

namespace Example;

use Psr\Log\AbstractLogger;
use Stringable;

final class StdoutLogger extends AbstractLogger {

	/**
	 * @param array<string,mixed> $context
	 */
	public function log($level, string|Stringable $message, array $context = []): void {
		$contextSummary = $context === [] ? '' : ' ' . json_encode($context);
		echo "[{$level}] {$message}{$contextSummary}\n";
	}

}
