<?php

namespace Oidc\Fakes;

/**
 * `psr/simple-cache` ships only the `InvalidArgumentException` interface, not a concrete class
 * - any real PSR-16 implementation supplies its own. This is the minimal concrete class a test
 * needs to actually throw one.
 */
final class SimpleCacheInvalidArgumentException extends \InvalidArgumentException implements \Psr\SimpleCache\InvalidArgumentException {

}
