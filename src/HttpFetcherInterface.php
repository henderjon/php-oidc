<?php

namespace Oidc;

use Oidc\Exceptions\HttpTransportException;

/**
 * The seam every other collaborator talks through instead of calling curl
 * directly - lets discovery, token requests, and JWKS fetches all be
 * tested against a fake instead of the network.
 */
interface HttpFetcherInterface {

	/**
	 * TLS verification is not a per-request concern: an implementation talking to real
	 * sockets is expected to always verify, full stop - see CurlHttpFetcher's constructor
	 * for the one narrow, loudly-logged exception meant for local development only.
	 *
	 * @param array<string,string> $headers Header name to value; no raw "Name: value" formatting.
	 * @throws HttpTransportException When the request cannot be completed at all (connection failure, timeout).
	 */
	public function fetch( string $url, ?string $body, array $headers = [] ): FetchResponse;

}
