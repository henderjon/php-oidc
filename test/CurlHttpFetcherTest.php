<?php

namespace Henderjon\Oidc;

use donatj\MockWebServer\MockWebServer;
use donatj\MockWebServer\Response;
use Henderjon\Oidc\Exceptions\HttpTransportException;
use PHPUnit\Framework\TestCase;

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

	public function testFetcherCanBeReusedAcrossCalls(): void {
		self::$server->setResponseOfPath('/first', new Response('first'));
		self::$server->setResponseOfPath('/second', new Response('second'));

		$fetcher = new CurlHttpFetcher;

		$this->assertSame('first', $fetcher->fetch($this->url('first'), null)->body);
		$this->assertSame('second', $fetcher->fetch($this->url('second'), null)->body);
	}

}
