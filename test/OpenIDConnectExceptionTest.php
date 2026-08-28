<?php

namespace Oidc;

use Oidc\Exceptions\OpenIDConnectException;
use PHPUnit\Framework\TestCase;

class OpenIDConnectExceptionTest extends TestCase {

	public function testGetStateReturnsTheConstructedValue(): void {
		$exception = new OpenIDConnectException('something failed', state: 'the-flow-state');

		$this->assertSame('the-flow-state', $exception->getState());
	}

	public function testGetStateDefaultsToNull(): void {
		$exception = new OpenIDConnectException('something failed');

		$this->assertNull($exception->getState());
	}

	public function testPreviousStillChainsAlongsideState(): void {
		$previous  = new \RuntimeException('the underlying cause');
		$exception = new OpenIDConnectException('something failed', state: 'the-flow-state', previous: $previous);

		$this->assertSame('the-flow-state', $exception->getState());
		$this->assertSame($previous, $exception->getPrevious());
	}

}
