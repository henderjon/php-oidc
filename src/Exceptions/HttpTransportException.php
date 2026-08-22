<?php

namespace Henderjon\Oidc\Exceptions;

/**
 * Thrown by the HTTP transport itself (connection failure, timeout) below
 * the level of any specific OIDC operation. Callers catch this and rewrap
 * it into whichever domain exception fits the operation they were
 * attempting (discovery, token request, userinfo, ...).
 */
class HttpTransportException extends OpenIDConnectException {

}
