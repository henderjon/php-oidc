<?php

namespace Oidc;

/**
 * How strictly RFC 7636 PKCE is enforced on the authorization code flow.
 *
 * `Disabled` never generates a verifier - no `code_challenge` is sent, and
 * none is sent back at token exchange. `Optional` and `Required` both send
 * a `code_challenge` on every redirect; they differ only in what happens if
 * the verifier is missing by the time the flow completes (evicted from the
 * cache, TTL expired, or the redirect and completion configs disagree):
 * `Optional` proceeds without one and lets the token endpoint decide,
 * `Required` fails closed with AuthenticationFailedException.
 */
enum PkceMode {

	case Disabled;
	case Optional;
	case Required;

}
