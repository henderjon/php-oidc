<?php

declare(strict_types=1);

require dirname(__DIR__, 2) . '/vendor/autoload.php';
require dirname(__DIR__) . '/src/SessionCache.php';
require dirname(__DIR__) . '/src/CollectingLogger.php';
require dirname(__DIR__) . '/src/views.php';

use Compliance\CollectingLogger;
use Compliance\SessionCache;
use Oidc\ClientAuthMethod;
use Oidc\CurlHttpFetcher;
use Oidc\Exceptions\OpenIDConnectException;
use Oidc\IncomingAuthorizationResponse;
use Oidc\OpenIDConnectClientConfig;
use Oidc\OpenIDConnectClientFactory;
use Oidc\PkceMode;

session_start();

/**
 * @return list<string>
 */
function splitList( string $raw ): array {
	$parts = preg_split('/[\s,]+/', trim($raw)) ?: [];

	return array_values(array_filter($parts, static fn ( string $part ): bool => $part !== ''));
}

/**
 * Rebuilds the same OpenIDConnectClientConfig on every request from the raw form values saved
 * in the session - start(), callback(), userinfo(), and refresh() all need an identical config,
 * and none of them can hold onto a live PHP object across the redirect out to the suite and
 * back.
 *
 * @param array<string,mixed> $raw
 */
function buildClientConfig( array $raw, string $redirectUrl ): OpenIDConnectClientConfig {
	$allowedHosts = splitList((string)($raw['allowedHosts'] ?? ''));
	$audience     = splitList((string)($raw['audience'] ?? ''));
	$maxLifetime  = trim((string)($raw['maxTokenLifetimeSeconds'] ?? ''));

	return new OpenIDConnectClientConfig(
		clientId: (string)($raw['clientId'] ?? ''),
		clientSecret: (string)($raw['clientSecret'] ?? ''),
		redirectUrl: $redirectUrl,
		providerUrl: trim((string)($raw['providerUrl'] ?? '')) !== '' ? trim((string)$raw['providerUrl']) : null,
		issuer: (string)($raw['issuer'] ?? ''),
		scopes: splitList((string)($raw['scopes'] ?? '')),
		audience: $audience === [] ? null : $audience,
		pkce: constant(PkceMode::class . '::' . (string)($raw['pkce'] ?? 'Disabled')),
		allowedHosts: $allowedHosts === [] ? null : $allowedHosts,
		allowedAlgorithms: splitList((string)($raw['allowedAlgorithms'] ?? 'RS256')) ?: [ 'RS256' ],
		maxTokenLifetimeSeconds: $maxLifetime !== '' ? (int)$maxLifetime : null,
		allowUntrustedAudiences: !empty($raw['allowUntrustedAudiences']),
		allowAnyHost: !empty($raw['allowAnyHost']),
		clientAuthMethod: constant(ClientAuthMethod::class . '::' . (string)($raw['clientAuthMethod'] ?? 'Basic')),
	);
}

function makeClient( CollectingLogger $logger ): \Oidc\OpenIDConnectClient {
	return (new OpenIDConnectClientFactory(new CurlHttpFetcher(logger: $logger), logger: $logger))
		->make(new SessionCache(), 'compliance-harness');
}

/**
 * @return array<string,mixed>|null
 */
function sessionConfig(): ?array {
	return $_SESSION['harness_config'] ?? null;
}

function render( string $title, string $body ): void {
	echo \Compliance\layout($title, $body);
}

$action = $_GET['action'] ?? 'home';

if( $action === 'home' ) {
	$config = sessionConfig() ?? [];
	$body   = \Compliance\setupForm($config);

	$result = $_SESSION['harness_result'] ?? null;

	if( is_array($result) ) {
		$body .= \Compliance\savedResultPanel($result);
	}

	render('Setup', $body);

	return;
}

if( $action === 'reset' ) {
	$config = sessionConfig() ?? [];

	$_SESSION = [
		'harness_config' => [
			'issuer'       => $config['issuer'] ?? '',
			'clientId'     => $config['clientId'] ?? '',
			'clientSecret' => $config['clientSecret'] ?? '',
			'responseType' => $config['responseType'] ?? 'code',
		],
	];

	header('Location: /index.php');

	return;
}

if( $action === 'start' && $_SERVER['REQUEST_METHOD'] === 'POST' ) {
	$raw = [
		'issuer'                   => $_POST['issuer'] ?? '',
		'providerUrl'              => $_POST['providerUrl'] ?? '',
		'clientId'                 => $_POST['clientId'] ?? '',
		'clientSecret'             => $_POST['clientSecret'] ?? '',
		'clientAuthMethod'         => $_POST['clientAuthMethod'] ?? 'Basic',
		'responseType'             => $_POST['responseType'] ?? 'code',
		'scopes'                   => $_POST['scopes'] ?? '',
		'pkce'                     => $_POST['pkce'] ?? 'Disabled',
		'allowedAlgorithms'        => $_POST['allowedAlgorithms'] ?? 'RS256',
		'allowedHosts'             => $_POST['allowedHosts'] ?? '',
		'allowAnyHost'             => isset($_POST['allowAnyHost']),
		'audience'                 => $_POST['audience'] ?? '',
		'allowUntrustedAudiences'  => isset($_POST['allowUntrustedAudiences']),
		'maxTokenLifetimeSeconds'  => $_POST['maxTokenLifetimeSeconds'] ?? '',
	];

	$_SESSION['harness_config'] = $raw;
	unset($_SESSION['harness_result']);

	$logger = new CollectingLogger();

	try {
		$config   = buildClientConfig($raw, \Compliance\callbackUrl());
		$client   = makeClient($logger);
		$redirect = match( $raw['responseType'] ) {
			'id_token'       => $client->buildImplicitFlowRedirect($config),
			'id_token token' => $client->buildImplicitFlowRedirectWithAccessToken($config),
			default          => $client->buildAuthorizationCodeRedirect($config),
		};
	} catch( OpenIDConnectException $e ) {
		render('Login failed', \Compliance\errorPanel('Could not start the login redirect', $e, $logger));

		return;
	}

	render('Ready to continue', \Compliance\continueToProviderPanel($redirect->url));

	return;
}

if( $action === 'callback' ) {
	$raw = sessionConfig();

	if( $raw === null ) {
		render('Callback', \Compliance\errorPanel('No saved configuration', new \RuntimeException('Start over from the home page - the session has no in-progress login.'), new CollectingLogger()));

		return;
	}

	// Implicit flow's default response mode (response_mode=fragment) delivers code/id_token/
	// state after "#", which is never sent to any server - only JavaScript running in the
	// browser can see it. A GET with none of those in the query string might just be that
	// fragment waiting to be read; render a relay page that reads location.hash and resubmits
	// it as real query params, rather than assuming the request is simply broken.
	$hasQueryParams = isset($_GET['code']) || isset($_GET['id_token']) || isset($_GET['error']);

	if( $_SERVER['REQUEST_METHOD'] !== 'POST' && !$hasQueryParams ) {
		render('Reading the fragment', \Compliance\fragmentRelayPanel());

		return;
	}

	$logger  = new CollectingLogger();
	$config  = buildClientConfig($raw, \Compliance\callbackUrl());
	$client  = makeClient($logger);

	// response_mode=form_post delivers code/state/id_token as a POST body instead of query
	// params - $_GET would be empty except for our own ?action=callback.
	$params     = $_SERVER['REQUEST_METHOD'] === 'POST' ? $_POST : $_GET;
	$request    = new IncomingAuthorizationResponse($params);
	$isImplicit = in_array($raw['responseType'] ?? 'code', [ 'id_token', 'id_token token' ], true);
	$flowLabel  = $isImplicit ? 'Implicit flow' : 'Authorization code flow';

	try {
		$result = $isImplicit
			? $client->completeImplicitFlow($config, $request)
			: $client->completeAuthorizationCodeFlow($config, $request);
	} catch( OpenIDConnectException $e ) {
		render('Callback failed', \Compliance\errorPanel($flowLabel, $e, $logger));

		return;
	}

	$_SESSION['harness_result'] = [
		'idToken'      => $result->idToken,
		'claims'       => $result->claims->all(),
		'accessToken'  => $result->accessToken,
		'refreshToken' => $result->refreshToken,
		'expiresIn'    => $result->expiresIn,
	];

	render('Callback succeeded', \Compliance\successPanel($flowLabel, $result->idToken, $result->claims, $result->accessToken, $result->refreshToken, $result->expiresIn, $logger));

	return;
}

if( $action === 'userinfo' ) {
	$raw    = sessionConfig();
	$result = $_SESSION['harness_result'] ?? null;

	if( $raw === null || !is_array($result) || $result['accessToken'] === null ) {
		render('UserInfo', \Compliance\errorPanel('No saved login', new \RuntimeException('Complete a login first - there is no access_token in this session.'), new CollectingLogger()));

		return;
	}

	$logger        = new CollectingLogger();
	$config        = buildClientConfig($raw, \Compliance\callbackUrl());
	$client        = makeClient($logger);
	$claimsSubject = (string)($result['claims']['sub'] ?? '');

	try {
		$claims = $client->fetchUserInfo($config, (string)$result['accessToken'], $claimsSubject);
	} catch( OpenIDConnectException $e ) {
		render('UserInfo failed', \Compliance\errorPanel('fetchUserInfo()', $e, $logger));

		return;
	}

	render('UserInfo succeeded', \Compliance\successPanel('fetchUserInfo()', $result['idToken'], $claims, $result['accessToken'], $result['refreshToken'], $result['expiresIn'], $logger));

	return;
}

if( $action === 'refresh' ) {
	$raw    = sessionConfig();
	$result = $_SESSION['harness_result'] ?? null;

	if( $raw === null || !is_array($result) || $result['refreshToken'] === null ) {
		render('Refresh', \Compliance\errorPanel('No refresh token', new \RuntimeException('There is no refresh_token in this session to redeem.'), new CollectingLogger()));

		return;
	}

	$logger = new CollectingLogger();
	$config = buildClientConfig($raw, \Compliance\callbackUrl());
	$client = makeClient($logger);

	try {
		$refreshed = $client->refresh($config, (string)$result['refreshToken'], (string)$result['idToken'], new \Oidc\Claims($result['claims']));
	} catch( OpenIDConnectException $e ) {
		render('Refresh failed', \Compliance\errorPanel('refresh()', $e, $logger));

		return;
	}

	$_SESSION['harness_result'] = [
		'idToken'      => $refreshed->idToken,
		'claims'       => $refreshed->claims->all(),
		'accessToken'  => $refreshed->accessToken,
		'refreshToken' => $refreshed->refreshToken,
		'expiresIn'    => $refreshed->expiresIn,
	];

	render('Refresh succeeded', \Compliance\successPanel('refresh()', $refreshed->idToken, $refreshed->claims, $refreshed->accessToken, $refreshed->refreshToken, $refreshed->expiresIn, $logger));

	return;
}

http_response_code(404);
render('Not found', '<h2>Unknown action</h2><p><a href="/index.php">Back to harness</a></p>');
