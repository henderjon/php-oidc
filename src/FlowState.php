<?php

namespace Henderjon\Oidc;

/**
 * The state and nonce for one in-flight authorization attempt. Both are
 * only null when nothing was ever stored, or it was already consumed.
 */
final class FlowState {

	public function __construct(
		public readonly ?string $state,
		public readonly ?string $nonce,
	) {
	}

}
