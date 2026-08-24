<?php

namespace Oidc;

use PHPUnit\Framework\TestCase;

class JsonContentTypePolicyTest extends TestCase {

	public function testApplicationJsonIsAcceptable(): void {
		$this->assertTrue(JsonContentTypePolicy::isAcceptable('application/json'));
	}

	public function testMissingContentTypeIsAcceptable(): void {
		// Several real providers omit the header entirely on an otherwise well-formed JSON
		// response - the body's own JSON-validity is checked separately regardless.
		$this->assertTrue(JsonContentTypePolicy::isAcceptable(null));
	}

	public function testComparisonIsCaseInsensitive(): void {
		$this->assertTrue(JsonContentTypePolicy::isAcceptable('Application/JSON'));
	}

	public function testUnrelatedContentTypeIsRejected(): void {
		$this->assertFalse(JsonContentTypePolicy::isAcceptable('text/html'));
	}

	public function testAdditionalAllowedTypeIsAccepted(): void {
		$this->assertTrue(JsonContentTypePolicy::isAcceptable('application/jwk-set+json', [ 'application/jwk-set+json' ]));
	}

	public function testAdditionalAllowedListDoesNotWidenOtherCalls(): void {
		$this->assertFalse(JsonContentTypePolicy::isAcceptable('application/jwk-set+json'));
	}

}
