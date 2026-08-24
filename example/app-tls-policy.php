<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/StdoutLogger.php';

use donatj\MockWebServer\MockWebServer;
use donatj\MockWebServer\Response;
use Example\StdoutLogger;
use Oidc\CurlHttpFetcher;

// CurlHttpFetcher is the one class in this library that talks to real sockets, so this
// example uses it directly (every other example fakes HttpFetcherInterface instead) - the
// behavior being demonstrated only exists at that layer. MockWebServer serves plain HTTP,
// not HTTPS, so this cannot demonstrate curl actually rejecting a bad certificate - only the
// diagnostic that fires while verification is disabled at all. There is no test transport in
// this repository's dependencies capable of serving an invalid/self-signed HTTPS endpoint.
$server = new MockWebServer;
$server->start();
$server->setResponseOfPath('/discovery', new Response('{}'));

$url = 'http://' . $server->getHost() . ':' . $server->getPort() . '/discovery';

echo "Default: TLS verification is always on, nothing is logged.\n";
(new CurlHttpFetcher(logger: new StdoutLogger))->fetch($url, null);
echo "(no output above - that is the point)\n\n";

echo "disableTlsVerificationForLocalDevelopmentOnly: true - every request logs a notice:\n";
$insecureFetcher = new CurlHttpFetcher(disableTlsVerificationForLocalDevelopmentOnly: true, logger: new StdoutLogger);
$insecureFetcher->fetch($url, null);
$insecureFetcher->fetch($url, null);
echo "(two requests, two notices - not a one-time message easy to miss in a log stream. Logged at\n";
echo "notice rather than something more severe, since this is expected noise for as long as local\n";
echo "development needs it active - a caller can filter this level down or silence it entirely.)\n";

$server->stop();
