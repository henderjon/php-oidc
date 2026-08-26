<?php

namespace Compliance;

use Psr\Log\AbstractLogger;

/**
 * Collects every log call made during one request instead of writing it anywhere, so the
 * result page can show it. php-oidc deliberately keeps its own exception messages generic
 * (see AGENTS.md's rule against exposing them to end users) and puts the real diagnostic
 * detail - the claim that mismatched, the endpoint that got rejected - only in the log.
 * This harness is a local debugging tool, not a production app, so showing that detail on
 * the page is exactly the point: it is what actually explains why a conformance test module
 * passed or failed.
 */
final class CollectingLogger extends AbstractLogger {

	/** @var list<array{level:string,message:string,context:array<string,mixed>}> */
	public array $entries = [];

	/**
	 * @param array<string,mixed> $context
	 */
	public function log( $level, string|\Stringable $message, array $context = [] ): void {
		$this->entries[] = [
			'level'   => (string)$level,
			'message' => (string)$message,
			'context' => $context,
		];
	}

}
