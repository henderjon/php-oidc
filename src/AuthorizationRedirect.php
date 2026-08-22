<?php

namespace Henderjon\Oidc;

/**
 * A URL to send the user-agent to next - a login redirect or a sign-out
 * redirect. The caller decides how to issue the redirect; this library
 * never emits a response itself.
 */
final class AuthorizationRedirect {

	public function __construct(
		public readonly string $url,
	) {
	}

}
