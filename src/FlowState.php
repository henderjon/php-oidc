<?php

namespace Oidc;

/**
 * The state and nonce for one in-flight authorization attempt. Only ever
 * constructed for an attempt that was actually started (state/nonce), or
 * matched and consumed (see AuthorizationStateStore) - there is no
 * "nothing was stored" representation, because AuthorizationStateStore
 * returns null instead of a FlowState in that case.
 */
final class FlowState {

	public function __construct(
		public readonly string $state,
		public readonly string $nonce,
		public readonly ?string $codeVerifier = null,
	) {
	}

}
