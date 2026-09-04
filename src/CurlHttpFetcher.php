<?php

namespace Oidc;

use Oidc\Exceptions\HttpTransportException;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * The one class in this module that talks to real sockets. Reuses a single
 * curl handle across calls so a burst of discovery/token/userinfo calls
 * does not open a new connection per request.
 *
 * Deliberately does not follow redirects: several calls here carry an
 * Authorization header, and blindly following a redirect would resend it
 * to whatever host the response named.
 *
 * TLS verification is not something any individual call can opt out of - there is no
 * `verifyTls` parameter on `fetch()`. The only way to disable it at all is
 * `$disableTlsVerificationForLocalDevelopmentOnly`, decided once for this instance's whole
 * lifetime rather than per request, with a name that cannot be mistaken for a normal
 * setting. Every single request made while it is active logs a diagnostic - not a one-time
 * notice easy to lose in a large log stream - because for as long as it is on, every request
 * this instance makes is vulnerable to a network-position attacker intercepting or forging
 * responses, including ones carrying bearer credentials. Logged at `alert`: unlike the
 * fail-open decisions elsewhere in this library that stay at `warning`/`notice`, this one
 * means every request this instance makes is actively unauthenticated, which warrants
 * standing out from routine operational noise for as long as it is active.
 *
 * The response body is bounded by `$maxResponseBytes` regardless of how fast or slow the
 * connection is - `CURLOPT_TIMEOUT` alone only bounds wall-clock time, so a fast connection
 * could otherwise still push an unbounded amount of data within that window. Enforced with a
 * `CURLOPT_WRITEFUNCTION` callback rather than `CURLOPT_MAXFILESIZE`, since the latter relies
 * on the server declaring `Content-Length` up front and does not reliably apply to chunked
 * HTTP responses. `CURLOPT_LOW_SPEED_LIMIT`/`CURLOPT_LOW_SPEED_TIME` add a second, narrower
 * check on top: a connection that stalls to a crawl fails fast instead of only being caught
 * once the full timeout elapses.
 */
final class CurlHttpFetcher implements HttpFetcherInterface {

	private const USER_AGENT = 'henderjon-php-oidc';

	/** A connection sustaining less than this many bytes/second for LOW_SPEED_TIME_SECONDS is treated as stalled. */
	private const LOW_SPEED_LIMIT_BYTES_PER_SECOND = 1;

	private const LOW_SPEED_TIME_SECONDS = 10;

	private ?\CurlHandle $handle = null;

	public function __construct(
		private readonly int $timeoutSeconds = 30,
		private readonly int $maxResponseBytes = 5 * 1024 * 1024,
		private readonly bool $disableTlsVerificationForLocalDevelopmentOnly = false,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	/**
	 * @param non-empty-string $url
	 */
	public function fetch( string $url, ?string $body, array $headers = [] ): FetchResponse {
		if( $this->disableTlsVerificationForLocalDevelopmentOnly ) {
			$this->logger->alert('OIDC: TLS certificate and hostname verification is disabled for this request - never use this outside local development', [ 'url' => $url ]);
		}

		// Header/body VALUES are never logged here, only whether a body is present and which
		// header names were sent - this class has no idea which of them carry a client_secret,
		// an authorization code, or a bearer token, since every caller (discovery, token,
		// userinfo, JWKS) shares this one seam. A caller that wants a value logged decides that,
		// and how much of it, for itself - see TokenEndpointClient and ClientAuthenticator.
		$this->logger->debug('OIDC: sending HTTP request', [
			'url'          => $url,
			'has_body'     => $body !== null,
			'header_names' => array_keys($headers),
		]);

		$handle = $this->getHandle($url);

		curl_setopt($handle, CURLOPT_URL, $url);
		curl_setopt($handle, CURLOPT_HTTPHEADER, $this->formatHeaders($headers));

		$buffer        = '';
		$exceededLimit = false;

		// Reset per call, same as CURLOPT_URL above - the buffer and flag it closes over must
		// not carry over from whatever the last call through this reused handle collected.
		curl_setopt($handle, CURLOPT_WRITEFUNCTION, function ( \CurlHandle $ch, string $chunk ) use ( &$buffer, &$exceededLimit ): int {
			if( strlen($buffer) + strlen($chunk) > $this->maxResponseBytes ) {
				$exceededLimit = true;

				// Any return value shorter than strlen($chunk) tells curl the write failed,
				// aborting the transfer immediately rather than buffering the rest of an
				// oversized response before rejecting it after the fact.
				return 0;
			}

			$buffer .= $chunk;

			return strlen($chunk);
		});

		if( $body === null ) {
			// CURLOPT_HTTPGET does not clear a CURLOPT_CUSTOMREQUEST left over from a prior POST
			// on this reused handle - without resetting it first, this "GET" would still be sent
			// as a bodyless POST, which some servers (e.g. Microsoft's JWKS endpoint) reject with
			// a 411 Length Required.
			curl_setopt($handle, CURLOPT_CUSTOMREQUEST, null);
			curl_setopt($handle, CURLOPT_HTTPGET, true);
		} else {
			curl_setopt($handle, CURLOPT_CUSTOMREQUEST, 'POST');
			curl_setopt($handle, CURLOPT_POSTFIELDS, $body);
		}

		$succeeded = curl_exec($handle);

		if( $succeeded === false ) {
			if( $exceededLimit ) {
				$this->logger->error('OIDC: response exceeded the maximum allowed size and was aborted', [
					'url'                => $url,
					'max_response_bytes' => $this->maxResponseBytes,
				]);

				throw new HttpTransportException(sprintf('Response from %s exceeded the maximum allowed size of %d bytes', $url, $this->maxResponseBytes));
			}

			// CURLE_OPERATION_TIMEDOUT covers connect timeout, total timeout, and a low-speed
			// abort alike - curl gives no distinct code for which one specifically fired, only
			// its own message text (included below), which is not a stable API to parse
			// further than that.
			if( curl_errno($handle) === CURLE_OPERATION_TIMEDOUT ) {
				$this->logger->error('OIDC: request was aborted by a connect, total, or low-speed timeout', [
					'url'   => $url,
					'error' => curl_error($handle),
				]);
			} else {
				$this->logger->error('OIDC: request to the provider failed', [
					'url'   => $url,
					'error' => curl_error($handle),
				]);
			}

			throw new HttpTransportException(sprintf('Request to %s failed: %s', $url, curl_error($handle)));
		}

		$contentType = curl_getinfo($handle, CURLINFO_CONTENT_TYPE);
		$status      = (int)curl_getinfo($handle, CURLINFO_HTTP_CODE);

		$this->logger->debug('OIDC: received HTTP response', [
			'url'          => $url,
			'http_status'  => $status,
			'content_type' => $contentType,
			'body_bytes'   => strlen($buffer),
			'elapsed_ms'   => round(curl_getinfo($handle, CURLINFO_TOTAL_TIME) * 1000, 1),
		]);

		return new FetchResponse(
			body: $buffer,
			status: $status,
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

	private function getHandle( string $url ): \CurlHandle {
		if( $this->handle === null ) {
			$this->handle = curl_init() ?: throw new \RuntimeException("Unable to initialize curl for {$url}");
			curl_setopt($this->handle, CURLOPT_CONNECTTIMEOUT, $this->timeoutSeconds);
			curl_setopt($this->handle, CURLOPT_TIMEOUT, $this->timeoutSeconds);
			curl_setopt($this->handle, CURLOPT_LOW_SPEED_LIMIT, self::LOW_SPEED_LIMIT_BYTES_PER_SECOND);
			curl_setopt($this->handle, CURLOPT_LOW_SPEED_TIME, self::LOW_SPEED_TIME_SECONDS);
			curl_setopt($this->handle, CURLOPT_USERAGENT, self::USER_AGENT);

			// Fixed for this instance's whole lifetime, not per request - see the class
			// docblock for why there is no per-call way to disable this.
			curl_setopt($this->handle, CURLOPT_SSL_VERIFYPEER, !$this->disableTlsVerificationForLocalDevelopmentOnly);
			curl_setopt($this->handle, CURLOPT_SSL_VERIFYHOST, $this->disableTlsVerificationForLocalDevelopmentOnly ? 0 : 2);

			// Never file://, gopher://, ldap://, or anything else curl happens to support -
			// only the two schemes this library ever legitimately calls. CURLOPT_REDIR_PROTOCOLS
			// is set for the same reason even though redirects are never followed (see class
			// docblock) - insurance against that changing later without this being revisited.
			curl_setopt($this->handle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
			curl_setopt($this->handle, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
		}

		return $this->handle;
	}

}
