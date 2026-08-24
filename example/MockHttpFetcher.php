<?php

declare(strict_types=1);

namespace Example;

use Oidc\FetchResponse;
use Oidc\HttpFetcherInterface;
use RuntimeException;

final class MockHttpFetcher implements HttpFetcherInterface {

	/** @var array<string,FetchResponse> */
	private array $responses = [];

	/** @var list<array{url: string, body: ?string, headers: array<string,string>}> */
	public array $requests = [];

	public function respondTo(string $url, FetchResponse $response): void {
		$this->responses[$url] = $response;
	}

	public function fetch(string $url, ?string $body, array $headers = []): FetchResponse {
		$this->requests[] = [
			'url' => $url,
			'body' => $body,
			'headers' => $headers,
		];

		if (!isset($this->responses[$url])) {
			throw new RuntimeException("No mock response configured for {$url}");
		}

		return $this->responses[$url];
	}

}
