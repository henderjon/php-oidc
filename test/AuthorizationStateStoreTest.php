<?php

namespace Henderjon\Oidc;

use Henderjon\Oidc\Fakes\InMemoryCache;
use PHPUnit\Framework\TestCase;

class AuthorizationStateStoreTest extends TestCase {

	private function makeStore(): AuthorizationStateStore {
		return new AuthorizationStateStore(new InMemoryCache, 'the-cache-key');
	}

	public function testStartGeneratesStateAndNonce(): void {
		$flow = $this->makeStore()->start();

		$this->assertNotNull($flow->state);
		$this->assertNotNull($flow->nonce);
		$this->assertNotSame($flow->state, $flow->nonce);
	}

	public function testConsumeReturnsWhatWasStarted(): void {
		$store   = $this->makeStore();
		$started = $store->start();

		$consumed = $store->consume();

		$this->assertSame($started->state, $consumed->state);
		$this->assertSame($started->nonce, $consumed->nonce);
	}

	public function testConsumeClearsTheStoredValues(): void {
		$store = $this->makeStore();
		$store->start();

		$store->consume();
		$second = $store->consume();

		$this->assertNull($second->state);
		$this->assertNull($second->nonce);
	}

	public function testConsumeWithoutStartReturnsAllNull(): void {
		$consumed = $this->makeStore()->consume();

		$this->assertNull($consumed->state);
		$this->assertNull($consumed->nonce);
	}

	public function testEachStartProducesADifferentStateAndNonce(): void {
		$store = $this->makeStore();

		$first  = $store->start();
		$second = $store->start();

		$this->assertNotSame($first->state, $second->state);
		$this->assertNotSame($first->nonce, $second->nonce);
	}

	public function testDifferentCacheKeysDoNotCollideOnASharedCache(): void {
		$cache = new InMemoryCache;
		$userA = new AuthorizationStateStore($cache, 'user-a');
		$userB = new AuthorizationStateStore($cache, 'user-b');

		$startedA = $userA->start();
		$startedB = $userB->start();

		$consumedA = $userA->consume();
		$consumedB = $userB->consume();

		$this->assertSame($startedA->state, $consumedA->state);
		$this->assertSame($startedA->nonce, $consumedA->nonce);
		$this->assertSame($startedB->state, $consumedB->state);
		$this->assertSame($startedB->nonce, $consumedB->nonce);
	}

}
