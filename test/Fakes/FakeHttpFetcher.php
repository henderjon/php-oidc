<?php

namespace Oidc\Fakes;

use Oidc\FetchResponse;
use Oidc\HttpFetcherInterface;

/**
 * A canned-response test double for HttpFetcherInterface, shared across
 * every collaborator test that needs to fake discovery/token/JWKS calls
 * without touching the network.
 */
final class FakeHttpFetcher implements HttpFetcherInterface {

	/** @var array<string,FetchResponse|\Throwable> */
	private array $responses = [];

	/** @var list<array{url: string, body: ?string, headers: array<string,string>, verifyTls: bool}> */
	public array $requests = [];

	public function respondTo( string $url, FetchResponse $response ): void {
		$this->responses[$url] = $response;
	}

	public function failWith( string $url, \Throwable $exception ): void {
		$this->responses[$url] = $exception;
	}

	public function fetch( string $url, ?string $body, array $headers = [], bool $verifyTls = true ): FetchResponse {
		$this->requests[] = [ 'url' => $url, 'body' => $body, 'headers' => $headers, 'verifyTls' => $verifyTls ];

		$configured = $this->responses[$url] ?? null;

		if( $configured instanceof \Throwable ) {
			throw $configured;
		}

		if( $configured instanceof FetchResponse ) {
			return $configured;
		}

		throw new \RuntimeException("FakeHttpFetcher has no configured response for {$url}");
	}

}
