<?php

namespace Oidc;

use Oidc\Exceptions\AuthorizationStateException;
use Oidc\Fakes\ArrayLogger;
use Oidc\Fakes\DeleteFailingCache;
use Oidc\Fakes\FailingCache;
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

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: cached authorization flow entry is not the expected shape', $records[0]['message']);
		$this->assertSame('some-state', $records[0]['context']['state']);
		$this->assertSame('string', $records[0]['context']['type']);
	}

	public function testConsumeLogsWhenNoFlowMatchesTheGivenState(): void {
		$logger = new ArrayLogger;

		$this->assertNull($this->makeStore($logger)->consume('never-started'));

		$records = $logger->recordsAt(LogLevel::ALERT);
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

	public function testConsumeTruncatesAnOverlongStateBeforeLogging(): void {
		$logger        = new ArrayLogger;
		$oversizedState = str_repeat('a', 5000);

		$this->assertNull($this->makeStore($logger)->consume($oversizedState));

		$records = $logger->recordsAt(LogLevel::ALERT);
		$this->assertCount(1, $records);
		$this->assertLessThan(100, strlen($records[0]['context']['state']));
		$this->assertStringStartsWith(str_repeat('a', 64), $records[0]['context']['state']);
		$this->assertStringEndsWith('(truncated)', $records[0]['context']['state']);
	}

	public function testConsumeLogsWhenDeleteFailsAfterASuccessfulMatch(): void {
		$logger = new ArrayLogger;
		$store  = new AuthorizationStateStore(new DeleteFailingCache, 'the-cache-key', logger: $logger);

		$started = $store->start();
		$consumed = $store->consume($started->state);

		// The lookup and shape were both fine - only delete()'s own confirmation failed - so
		// the caller still gets a usable flow back. This must not fail closed on top of the
		// notice; that would make an unconfirmed delete look like a missing flow instead.
		$this->assertNotNull($consumed);

		$records = $logger->recordsAt(LogLevel::NOTICE);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: consumed authorization flow entry may not have been cleared from the cache', $records[0]['message']);
		$this->assertSame($started->state, $records[0]['context']['state']);
	}

	public function testConsumeWithoutAMatchDoesNotLogAboutDeleteFailing(): void {
		$logger = new ArrayLogger;
		$store  = new AuthorizationStateStore(new DeleteFailingCache, 'the-cache-key', logger: $logger);

		$store->consume('never-started');

		// Nothing was found to begin with, so delete() failing here is meaningless - only
		// the "no pending flow found" alert should fire, not a second one about deletion.
		$records = $logger->records;
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: no pending authorization flow found for the given state', $records[0]['message']);
	}

	public function testStartThrowsWhenTheCacheWriteFails(): void {
		$store = new AuthorizationStateStore(new FailingCache);

		$this->expectException(AuthorizationStateException::class);

		$store->start();
	}

	public function testStartLogsWhenTheCacheWriteFails(): void {
		$logger = new ArrayLogger;
		$store  = new AuthorizationStateStore(new FailingCache, logger: $logger);

		try {
			$store->start();
			$this->fail('Expected AuthorizationStateException to be thrown');
		} catch( AuthorizationStateException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame('OIDC: failed to persist a new authorization attempt', $records[0]['message']);
		$this->assertIsString($records[0]['context']['state']);
	}

}
