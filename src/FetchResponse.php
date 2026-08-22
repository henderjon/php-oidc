<?php

namespace Oidc;

final class FetchResponse {

	public function __construct(
		public readonly string $body,
		public readonly int $status,
		public readonly ?string $contentType = null,
	) {
	}

}
