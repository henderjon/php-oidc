<?php

namespace Oidc;

/**
 * Which of OpenID Connect Core 1.0 §9's Client Authentication methods
 * `ClientAuthenticator` uses for a confidential client. `private_key_jwt` is
 * not listed here yet - it needs a caller-supplied signing key, which this
 * library has no way to receive today, tracked as a separate, larger piece of
 * work.
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

	/**
	 * A short-lived JWT signed with HMAC-SHA256, keyed by the client secret, sent as
	 * `client_assertion` instead of the secret itself. The secret never goes on the wire. HS256
	 * needs a key of at least 32 bytes (RFC 7518 §3.2); a shorter client secret fails before any
	 * request is sent.
	 */
	case ClientSecretJwt;

}
