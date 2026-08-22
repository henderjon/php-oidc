<?php

namespace Oidc;

use Oidc\Fakes\ArrayLogger;
use Oidc\Fakes\InMemoryCache;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

class AuthorizationStateStoreTest extends TestCase {

	private function makeStore( ?ArrayLogger $logger = null ): AuthorizationStateStore {
		return new AuthorizationStateStore(new InMemoryCache, 'the-cache-key', logger: $logger ?? new ArrayLogger);
	}

	public function testStartGeneratesStateAndNonce(): void {
		$flow = $this->makeStore()->start();

		$this->assertNotSame('', $flow->state);
		$this->assertNotSame('', $flow->nonce);
		$this->assertNotSame($flow->state, $flow->nonce);
	}

	public function testConsumeReturnsWhatWasStarted(): void {
		$store   = $this->makeStore();
		$started = $store->start();

		$consumed = $store->consume($started->state);

		$this->assertNotNull($consumed);
		$this->assertSame($started->state, $consumed->state);
		$this->assertSame($started->nonce, $consumed->nonce);
	}

	public function testConsumeClearsTheStoredValues(): void {
		$store   = $this->makeStore();
		$started = $store->start();

		$store->consume($started->state);
		$second = $store->consume($started->state);

		$this->assertNull($second);
	}

	public function testConsumeWithoutAMatchingStartReturnsNull(): void {
		$this->assertNull($this->makeStore()->consume('never-started'));
	}

	public function testStartWithoutACodeVerifierLeavesItNull(): void {
		$flow = $this->makeStore()->start();

		$this->assertNull($flow->codeVerifier);
	}

	public function testConsumeReturnsTheCodeVerifierThatWasStarted(): void {
		$store   = $this->makeStore();
		$started = $store->start(codeVerifier: 'the-code-verifier');

		$consumed = $store->consume($started->state);

		$this->assertSame('the-code-verifier', $started->codeVerifier);
		$this->assertSame('the-code-verifier', $consumed?->codeVerifier);
	}

	public function testEachStartProducesADifferentStateAndNonce(): void {
		$store = $this->makeStore();

		$first  = $store->start();
		$second = $store->start();

		$this->assertNotSame($first->state, $second->state);
		$this->assertNotSame($first->nonce, $second->nonce);
	}

	public function testConcurrentStartsOnTheSameStoreDoNotCollide(): void {
		$store = $this->makeStore();

		$first  = $store->start();
		$second = $store->start();

		$consumedFirst  = $store->consume($first->state);
		$consumedSecond = $store->consume($second->state);

		$this->assertSame($first->nonce, $consumedFirst?->nonce);
		$this->assertSame($second->nonce, $consumedSecond?->nonce);
	}

	public function testConsumingOneOfTwoConcurrentStartsLeavesTheOtherIntact(): void {
		$store = $this->makeStore();

		$first  = $store->start();
		$second = $store->start();

		$store->consume($first->state);

		$this->assertSame($second->nonce, $store->consume($second->state)?->nonce);
	}

	public function testDifferentCacheKeysDoNotCollideOnASharedCache(): void {
		$cache = new InMemoryCache;
		$userA = new AuthorizationStateStore($cache, 'user-a');
		$userB = new AuthorizationStateStore($cache, 'user-b');

		$startedA = $userA->start();
		$startedB = $userB->start();

		$consumedA = $userA->consume($startedA->state);
		$consumedB = $userB->consume($startedB->state);

		$this->assertSame($startedA->nonce, $consumedA?->nonce);
		$this->assertSame($startedB->nonce, $consumedB?->nonce);
	}

	public function testConsumeReturnsNullWhenTheCachedValueIsNotTheExpectedShape(): void {
		$cache = new InMemoryCache;
		$cache->set('henderjon.oidc.flow.the-cache-key.some-state', 'not-an-array', 600);

		$logger = new ArrayLogger;
		$store  = new AuthorizationStateStore($cache, 'the-cache-key', logger: $logger);

		$this->assertNull($store->consume('some-state'));

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: cached authorization flow entry is not the expected shape', $records[0]['message']);
		$this->assertSame('some-state', $records[0]['context']['state']);
		$this->assertSame('string', $records[0]['context']['type']);
	}

	public function testConsumeLogsWhenNoFlowMatchesTheGivenState(): void {
		$logger = new ArrayLogger;

		$this->assertNull($this->makeStore($logger)->consume('never-started'));

		$records = $logger->recordsAt(LogLevel::WARNING);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: no pending authorization flow found for the given state', $records[0]['message']);
		$this->assertSame('never-started', $records[0]['context']['state']);
	}

	public function testConsumeDoesNotLogOnASuccessfulMatch(): void {
		$logger = new ArrayLogger;
		$store  = $this->makeStore($logger);
		$started = $store->start();

		$store->consume($started->state);

		$this->assertSame([], $logger->records);
	}

}
