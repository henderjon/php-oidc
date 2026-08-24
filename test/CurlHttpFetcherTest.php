<?php

namespace Oidc;

use donatj\MockWebServer\DelayedResponse;
use donatj\MockWebServer\MockWebServer;
use donatj\MockWebServer\Response;
use Oidc\Exceptions\HttpTransportException;
use Oidc\Fakes\ArrayLogger;
use PHPUnit\Framework\TestCase;
use Psr\Log\LogLevel;

class CurlHttpFetcherTest extends TestCase {

	private static MockWebServer $server;

	public static function setUpBeforeClass(): void {
		self::$server = new MockWebServer;
		self::$server->start();
	}

	public static function tearDownAfterClass(): void {
		self::$server->stop();
	}

	/**
	 * @return non-empty-string
	 */
	private function url( string $path ): string {
		return 'http://' . self::$server->getHost() . ':' . self::$server->getPort() . '/' . $path;
	}

	public function testFetchGet(): void {
		self::$server->setResponseOfPath('/discovery', new Response('{"issuer":"https://example.com"}', [ 'Content-Type' => 'application/json' ], 200));

		$fetcher  = new CurlHttpFetcher;
		$response = $fetcher->fetch($this->url('discovery'), null);

		$this->assertSame('{"issuer":"https://example.com"}', $response->body);
		$this->assertSame(200, $response->status);
		$this->assertSame('application/json', $response->contentType);
	}

	public function testFetchGetDoesNotSendABody(): void {
		self::$server->setResponseOfPath('/discovery', new Response('{}'));

		$fetcher = new CurlHttpFetcher;
		$fetcher->fetch($this->url('discovery'), null);

		$this->assertSame('', self::$server->getLastRequest()->getInput());
		$this->assertSame('GET', self::$server->getLastRequest()->getRequestMethod());
	}

	public function testFetchPostSendsBodyAndHeaders(): void {
		self::$server->setResponseOfPath('/token', new Response('{"access_token":"abc"}'));

		$fetcher = new CurlHttpFetcher;
		$fetcher->fetch($this->url('token'), 'grant_type=client_credentials', [ 'Authorization' => 'Basic xyz' ]);

		$request = self::$server->getLastRequest();

		$this->assertSame('POST', $request->getRequestMethod());
		$this->assertSame('grant_type=client_credentials', $request->getInput());
		$this->assertSame('Basic xyz', $request->getHeaders()['Authorization']);
	}

	public function testFetchStripsContentTypeParameters(): void {
		self::$server->setResponseOfPath('/discovery', new Response('{}', [ 'Content-Type' => 'application/json; charset=utf-8' ], 200));

		$fetcher  = new CurlHttpFetcher;
		$response = $fetcher->fetch($this->url('discovery'), null);

		$this->assertSame('application/json', $response->contentType);
	}

	public function testFetchReturnsNonSuccessStatus(): void {
		self::$server->setResponseOfPath('/token', new Response('{"error":"invalid_client"}', [], 401));

		$fetcher  = new CurlHttpFetcher;
		$response = $fetcher->fetch($this->url('token'), 'grant_type=client_credentials');

		$this->assertSame(401, $response->status);
		$this->assertSame('{"error":"invalid_client"}', $response->body);
	}

	public function testFetchThrowsOnConnectionFailure(): void {
		$fetcher = new CurlHttpFetcher(timeoutSeconds: 1);

		$this->expectException(HttpTransportException::class);

		// Nothing listens on this port on localhost.
		$fetcher->fetch('http://127.0.0.1:1/unreachable', null);
	}

	public function testFetchRejectsDisallowedSchemesAtTheCurlLevel(): void {
		// UrlPolicy is the higher-level gate a caller is expected to check first, but this
		// class must refuse file://, gopher://, and everything else curl happens to support
		// on its own too - not rely solely on every caller remembering to check first.
		$fetcher = new CurlHttpFetcher;

		$this->expectException(HttpTransportException::class);

		$fetcher->fetch('file:///etc/passwd', null);
	}

	public function testFetchGetAfterPostSendsAnActualGetNotALeftoverPost(): void {
		self::$server->setResponseOfPath('/token', new Response('{"access_token":"abc"}'));
		self::$server->setResponseOfPath('/jwks', new Response('{"keys":[]}'));

		$fetcher = new CurlHttpFetcher;
		$fetcher->fetch($this->url('token'), 'grant_type=client_credentials');
		$fetcher->fetch($this->url('jwks'), null);

		$this->assertSame('GET', self::$server->getLastRequest()->getRequestMethod());
	}

	public function testFetchGetAfterPostDoesNotSendALeftoverBody(): void {
		self::$server->setResponseOfPath('/token', new Response('{"access_token":"abc"}'));
		self::$server->setResponseOfPath('/jwks', new Response('{"keys":[]}'));

		$fetcher = new CurlHttpFetcher;
		$fetcher->fetch($this->url('token'), 'grant_type=client_credentials');
		$fetcher->fetch($this->url('jwks'), null);

		$this->assertSame('', self::$server->getLastRequest()->getInput());
	}

	public function testFetchGetAfterPostDoesNotLeakTheAuthorizationHeader(): void {
		self::$server->setResponseOfPath('/token', new Response('{"access_token":"abc"}'));
		self::$server->setResponseOfPath('/jwks', new Response('{"keys":[]}'));

		$fetcher = new CurlHttpFetcher;
		$fetcher->fetch($this->url('token'), 'grant_type=client_credentials', [ 'Authorization' => 'Bearer secret-token' ]);
		$fetcher->fetch($this->url('jwks'), null);

		$this->assertArrayNotHasKey('Authorization', self::$server->getLastRequest()->getHeaders());
	}

	public function testFetchPostAfterGetSendsTheNewBody(): void {
		self::$server->setResponseOfPath('/discovery', new Response('{}'));
		self::$server->setResponseOfPath('/token', new Response('{"access_token":"abc"}'));

		$fetcher = new CurlHttpFetcher;
		$fetcher->fetch($this->url('discovery'), null);
		$fetcher->fetch($this->url('token'), 'grant_type=client_credentials');

		$request = self::$server->getLastRequest();

		$this->assertSame('POST', $request->getRequestMethod());
		$this->assertSame('grant_type=client_credentials', $request->getInput());
	}

	public function testFetcherCanBeReusedAcrossCalls(): void {
		self::$server->setResponseOfPath('/first', new Response('first'));
		self::$server->setResponseOfPath('/second', new Response('second'));

		$fetcher = new CurlHttpFetcher;

		$this->assertSame('first', $fetcher->fetch($this->url('first'), null)->body);
		$this->assertSame('second', $fetcher->fetch($this->url('second'), null)->body);
	}

	public function testDefaultDoesNotLogAnything(): void {
		self::$server->setResponseOfPath('/discovery', new Response('{}'));

		$logger  = new ArrayLogger;
		$fetcher = new CurlHttpFetcher(logger: $logger);
		$fetcher->fetch($this->url('discovery'), null);

		$this->assertSame([], $logger->records);
	}

	public function testDisablingTlsVerificationLogsAnAlertOnEveryRequest(): void {
		self::$server->setResponseOfPath('/first', new Response('first'));
		self::$server->setResponseOfPath('/second', new Response('second'));

		$logger  = new ArrayLogger;
		$fetcher = new CurlHttpFetcher(disableTlsVerificationForLocalDevelopmentOnly: true, logger: $logger);
		$fetcher->fetch($this->url('first'), null);
		$fetcher->fetch($this->url('second'), null);

		// A prominent diagnostic means every request, not a one-time notice easy to lose in a
		// large log stream - two requests must produce two log records, not one.
		$records = $logger->recordsAt(LogLevel::ALERT);
		$this->assertCount(2, $records);
		$this->assertSame($this->url('first'), $records[0]['context']['url']);
		$this->assertSame($this->url('second'), $records[1]['context']['url']);
	}

	public function testResponseAtOrUnderTheMaxSizeSucceeds(): void {
		self::$server->setResponseOfPath('/discovery', new Response('0123456789'));

		$fetcher  = new CurlHttpFetcher(maxResponseBytes: 10);
		$response = $fetcher->fetch($this->url('discovery'), null);

		$this->assertSame('0123456789', $response->body);
	}

	public function testResponseOverTheMaxSizeThrows(): void {
		self::$server->setResponseOfPath('/discovery', new Response('01234567890'));

		$fetcher = new CurlHttpFetcher(maxResponseBytes: 10);

		$this->expectException(HttpTransportException::class);
		$this->expectExceptionMessage('exceeded the maximum allowed size of 10 bytes');

		$fetcher->fetch($this->url('discovery'), null);
	}

	public function testMaxSizeIsEnforcedPerCallNotCumulativelyAcrossAReusedHandle(): void {
		self::$server->setResponseOfPath('/first', new Response('0123456789'));
		self::$server->setResponseOfPath('/second', new Response('0123456789'));

		// Ten bytes each, twenty combined - if the byte count carried over across calls on
		// this reused handle instead of resetting per call, the second fetch would wrongly
		// look like it exceeded a 10-byte cap.
		$fetcher = new CurlHttpFetcher(maxResponseBytes: 10);

		$this->assertSame('0123456789', $fetcher->fetch($this->url('first'), null)->body);
		$this->assertSame('0123456789', $fetcher->fetch($this->url('second'), null)->body);
	}

	public function testExceedingTheMaxSizeLogsAnError(): void {
		self::$server->setResponseOfPath('/discovery', new Response('01234567890'));

		$logger  = new ArrayLogger;
		$fetcher = new CurlHttpFetcher(maxResponseBytes: 10, logger: $logger);

		try {
			$fetcher->fetch($this->url('discovery'), null);
			$this->fail('Expected HttpTransportException to be thrown');
		} catch( HttpTransportException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame($this->url('discovery'), $records[0]['context']['url']);
		$this->assertSame(10, $records[0]['context']['max_response_bytes']);
	}

	public function testTimeoutLogsAnError(): void {
		self::$server->setResponseOfPath('/slow', new DelayedResponse(new Response('{}'), 2_000_000));

		$logger  = new ArrayLogger;
		$fetcher = new CurlHttpFetcher(timeoutSeconds: 1, logger: $logger);

		try {
			$fetcher->fetch($this->url('slow'), null);
			$this->fail('Expected HttpTransportException to be thrown');
		} catch( HttpTransportException ) {
		}

		$records = $logger->recordsAt(LogLevel::ERROR);
		$this->assertCount(1, $records);
		$this->assertSame($this->url('slow'), $records[0]['context']['url']);
	}

}
