<?php

namespace Oidc;

/**
 * The `error`/`error_description`/`error_uri` triple a provider hands back on failure - RFC
 * 6749 §4.1.2.1 (authorization callback) and §5.2 (token endpoint) via a JSON body, RFC 6750
 * §3 / OpenID Connect Core 1.0 §5.3.3 (UserInfo endpoint) via the WWW-Authenticate header.
 * One shape for all three sources, so a caller catching any exception that carries one checks
 * it the same way regardless of where it came from. See Exceptions\ProviderErrorAwareInterface.
 *
 * `error` is the only field RFC 6749 requires when an error is reported at all;
 * `errorDescription`/`errorUri` are both OPTIONAL and commonly absent.
 */
final class ProviderError {

	public function __construct(
		public readonly ?string $error = null,
		public readonly ?string $errorDescription = null,
		public readonly ?string $errorUri = null,
	) {
	}

}
