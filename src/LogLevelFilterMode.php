<?php

namespace Oidc;

/**
 * How LogLevelFilterLogger's `$levels` is interpreted.
 *
 * `AllowList` (the default): only a level named in `$levels` is forwarded - an empty array
 * means nothing passes, including a level nobody has named yet. `DenyList`: every level is
 * forwarded except the ones named in `$levels` - an empty array means nothing is excluded, so
 * everything passes, including a level neither PSR-3 nor the caller has defined yet. See
 * LogLevelFilterLogger's own docblock for the four patterns this expresses together with
 * `$levels`.
 */
enum LogLevelFilterMode {

	case AllowList;
	case DenyList;

}
