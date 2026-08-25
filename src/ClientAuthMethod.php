<?php

namespace Oidc;

/**
 * Which of OpenID Connect Core 1.0 §9's Client Authentication methods
 * `ClientAuthenticator` uses for a confidential client. `client_secret_jwt`
 * and `private_key_jwt` are not listed here yet - both need a signed JWT
 * assertion, tracked as a separate, larger piece of work.
 *
 * Has no effect on a public client (empty `clientSecret`) - there is no
 * secret to authenticate with under either method, so that case always
 * falls back to identifying via a bare `client_id` in the body, same as
 * before this enum existed.
 */
enum ClientAuthMethod {

	/** HTTP Basic (RFC 6749 §2.3.1) - the spec default when no method is registered. */
	case Basic;

	/** Client credentials in the request body instead of the Authorization header. */
	case Post;

}
