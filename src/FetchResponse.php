<?php

namespace Oidc;

final class FetchResponse {

	/**
	 * @param ?string $wwwAuthenticate The `WWW-Authenticate` response header verbatim, when
	 *                                 present - the one response header this library actually
	 *                                 needs (RFC 6750 §3: a resource server, the UserInfo
	 *                                 endpoint here, MAY return `error`/`error_description`/
	 *                                 `error_uri` this way instead of in a JSON body). Every
	 *                                 other header is deliberately not captured - see
	 *                                 CurlHttpFetcher's own docblock for why request headers
	 *                                 stay unlogged, and this class does not need a general
	 *                                 response-header concept just to reach this one value.
	 */
	public function __construct(
		public readonly string $body,
		public readonly int $status,
		public readonly ?string $contentType = null,
		public readonly ?string $wwwAuthenticate = null,
	) {
	}

}
