<?php

namespace Henderjon\Oidc;

use Henderjon\Oidc\Exceptions\HttpTransportException;

/**
 * The one class in this module that talks to real sockets. Reuses a single
 * curl handle across calls so a burst of discovery/token/userinfo calls
 * does not open a new connection per request.
 *
 * Deliberately does not follow redirects: several calls here carry an
 * Authorization header, and blindly following a redirect would resend it
 * to whatever host the response named.
 */
final class CurlHttpFetcher implements HttpFetcherInterface {

	private const USER_AGENT = 'henderjon-php-oidc';

	private ?\CurlHandle $handle = null;

	public function __construct(
		private readonly int $timeoutSeconds = 30,
	) {
	}

	/**
	 * @param non-empty-string $url
	 */
	public function fetch( string $url, ?string $body, array $headers = [], bool $verifyTls = true ): FetchResponse {
		$handle = $this->getHandle();

		curl_setopt($handle, CURLOPT_URL, $url);
		curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, $verifyTls);
		curl_setopt($handle, CURLOPT_SSL_VERIFYHOST, $verifyTls ? 2 : 0);
		curl_setopt($handle, CURLOPT_HTTPHEADER, $this->formatHeaders($headers));

		if( $body === null ) {
			curl_setopt($handle, CURLOPT_HTTPGET, true);
		} else {
			curl_setopt($handle, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
		}

		$response = curl_exec($handle);

		if( $response === false ) {
			throw new HttpTransportException(sprintf('Request to %s failed: %s', $url, curl_error($handle)));
		}

		\assert(is_string($response));

		$contentType = curl_getinfo($handle, CURLINFO_CONTENT_TYPE);

		return new FetchResponse(
			body: $response,
			status: (int)curl_getinfo($handle, CURLINFO_HTTP_CODE),
			contentType: is_string($contentType) ? $this->stripParameters($contentType) : null,
		);
	}

	/**
	 * @param array<string,string> $headers
	 * @return list<string>
	 */
	private function formatHeaders( array $headers ): array {
		$formatted = [];
		foreach( $headers as $name => $value ) {
			$formatted[] = "{$name}: {$value}";
		}

		return $formatted;
	}

	private function stripParameters( string $contentType ): string {
		return trim(explode(';', $contentType, 2)[0]);
	}

	private function getHandle(): \CurlHandle {
		if( $this->handle === null ) {
			$this->handle = curl_init() ?: throw new \RuntimeException('Unable to initialize curl');
			curl_setopt($this->handle, CURLOPT_RETURNTRANSFER, true);
			curl_setopt($this->handle, CURLOPT_CONNECTTIMEOUT, $this->timeoutSeconds);
			curl_setopt($this->handle, CURLOPT_TIMEOUT, $this->timeoutSeconds);
			curl_setopt($this->handle, CURLOPT_USERAGENT, self::USER_AGENT);
		}

		return $this->handle;
	}

}
