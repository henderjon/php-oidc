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
 * responses, including ones carrying bearer credentials. Logged at `notice`, not a more
 * severe level: this is expected, intentional noise for as long as local development needs
 * it active, not an error - and `notice` gives a caller an easy level to filter down or
 * silence entirely for that stretch of time, without needing to silence anything more
 * severe to do it.
 */
final class CurlHttpFetcher implements HttpFetcherInterface {

	private const USER_AGENT = 'henderjon-php-oidc';

	private ?\CurlHandle $handle = null;

	public function __construct(
		private readonly int $timeoutSeconds = 30,
		private readonly bool $disableTlsVerificationForLocalDevelopmentOnly = false,
		private readonly LoggerInterface $logger = new NullLogger,
	) {
	}

	/**
	 * @param non-empty-string $url
	 */
	public function fetch( string $url, ?string $body, array $headers = [] ): FetchResponse {
		if( $this->disableTlsVerificationForLocalDevelopmentOnly ) {
			$this->logger->notice('OIDC: TLS certificate and hostname verification is disabled for this request - never use this outside local development', [ 'url' => $url ]);
		}

		$handle = $this->getHandle();

		curl_setopt($handle, CURLOPT_URL, $url);
		curl_setopt($handle, CURLOPT_HTTPHEADER, $this->formatHeaders($headers));

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
