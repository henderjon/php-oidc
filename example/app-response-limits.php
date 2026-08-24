<?php

declare(strict_types=1);

require dirname(__DIR__) . '/vendor/autoload.php';
require __DIR__ . '/InMemoryCache.php';
require __DIR__ . '/MockHttpFetcher.php';
require __DIR__ . '/StdoutLogger.php';

use donatj\MockWebServer\MockWebServer;
use donatj\MockWebServer\Response;
use Example\InMemoryCache;
use Example\MockHttpFetcher;
use Example\StdoutLogger;
use Oidc\CurlHttpFetcher;
use Oidc\Exceptions\HttpTransportException;
use Oidc\Exceptions\ProviderDiscoveryException;
use Oidc\FetchResponse;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;

// Byte cap: uses CurlHttpFetcher directly against a real local server, the same reason
// app-tls-policy.php does - this behavior only exists at that layer.
$server = new MockWebServer;
$server->start();
$server->setResponseOfPath('/small', new Response('a small response'));
$server->setResponseOfPath('/huge', new Response(str_repeat('a', 1024)));

$url = fn (string $path): string => 'http://' . $server->getHost() . ':' . $server->getPort() . '/' . $path;

$fetcher = new CurlHttpFetcher(maxResponseBytes: 100, logger: new StdoutLogger);
echo "A 17-byte response under a 100-byte cap: {$fetcher->fetch($url('small'), null)->body}\n\n";

try {
	$fetcher->fetch($url('huge'), null);
} catch (HttpTransportException $e) {
	echo "A 1024-byte response over the same cap is aborted: {$e->getMessage()}\n\n";
}

$server->stop();

// Content-Type validation: uses the full client, the same way app-url-policy.php does -
// this is checked before a discovery document's body is ever parsed as JSON.
$providerUrl = 'https://mock-idp.example.test';
$discoveryEndpoint = $providerUrl . '/.well-known/openid-configuration';

$http = new MockHttpFetcher;
$http->respondTo($discoveryEndpoint, new FetchResponse(
	'<html><body>this looks nothing like a discovery document</body></html>',
	200,
	'text/html',
));

$config = new OpenIDConnectClientConfig(
	clientId: 'example-client',
	clientSecret: 'example-secret',
	redirectUrl: 'https://application.example.test/oidc/callback',
	providerUrl: $providerUrl,
	issuer: $providerUrl,
);

$client = (new OpenIDConnectClientFactory($http))->make(new InMemoryCache());

try {
	$client->buildAuthorizationCodeRedirect($config);
} catch (ProviderDiscoveryException $e) {
	echo "A discovery response with Content-Type: text/html is rejected before parsing: {$e->getMessage()}\n";
}
