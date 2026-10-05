<?php

namespace Oidc\Exceptions;

/**
 * Thrown when the config asks for something the library refuses to do safely, such as sending
 * `max_age` through `extraAuthParams`, where nothing would check `auth_time` on the way back.
 * Its own type, so a caller can tell a fixable setup mistake from a failure at the provider.
 */
class ConfigurationException extends OpenIDConnectException {

}
