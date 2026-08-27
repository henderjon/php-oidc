<?php

namespace Compliance;

use Oidc\Claims;

function escape( ?string $value ): string {
	return htmlspecialchars($value ?? '', ENT_QUOTES, 'UTF-8');
}

/**
 * Shared page shell - CSS lifted from local/styleguide.html (topbar, typography, code blocks,
 * tables, alert boxes), recolored to PHP's brand purple, the same treatment docs/index.html
 * already uses. A success/status vocabulary is added on top - the style guide never
 * anticipated a pass/fail result page - kept in the same weight and restraint as its existing
 * alert-box/warning treatment rather than inventing a whole new visual language.
 */
function layout( string $title, string $bodyHtml ): string {
	$escapedTitle = escape($title);

	return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#4F5B93">
  <title>{$escapedTitle} - php-oidc Compliance Harness</title>
  <style>
    body {
      margin: 0;
      font-family: Arial, sans-serif;
      line-height: 1.3;
      color: #222;
    }

    pre, code {
      font-family: Menlo, monospace;
      font-size: 0.875rem;
    }

    pre {
      line-height: 1.4;
      overflow-x: auto;
      background: #efefef;
      padding: 0.625rem;
      border-radius: 0.3125rem;
      margin: 1.25rem 0;
      text-align: left;
      white-space: pre-wrap;
      word-break: break-word;
    }

    h1, h2, h3, h4 {
      margin: 1.25rem 0;
      color: #4F5B93;
      font-weight: bold;
    }

    h1 { font-size: 1.75rem; line-height: 1; }
    h1 .text-muted { color: #777; font-weight: normal; font-size: 1rem; }

    h2 {
      font-size: 1.25rem;
      background: #ece9f5;
      padding: 0.5rem;
      line-height: 1.25;
      font-weight: normal;
    }

    h3 { font-size: 1.1rem; margin: 1.25rem 0 0.5rem; }

    a { color: #4F5B93; text-decoration: none; }
    a:hover { text-decoration: underline; }

    .container {
      padding: 0 1.25rem 2.5rem;
      max-width: 50rem;
      margin: 0;
    }

    p, li { max-width: 50rem; }
    p, ul, ol { margin: 1rem 0; }

    #topbar {
      background: #ece9f5;
      height: 4rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      padding: 0 1.25rem;
    }

    .top-heading { font-size: 1.1rem; }
    .top-heading a { color: #222; text-decoration: none; }
    .top-nav a { margin-left: 1rem; }

    .button {
      padding: 0.625rem 1rem;
      font-size: 1rem;
      border-radius: 0.3125rem;
      border: 1px solid #4F5B93;
      display: inline-block;
      margin: 0.3125rem 0.125rem 0.3125rem 0;
      text-decoration: none;
      cursor: pointer;
      background: white;
      color: #4F5B93;
      font-family: inherit;
    }

    .button-primary { color: white; background: #4F5B93; }
    .button-secondary { color: #222; background: #ece9f5; border-color: #ece9f5; }
    .button:hover { opacity: 0.9; }

    table { border-collapse: collapse; margin: 1rem 0; width: 100%; }
    table td, table th { padding: 0.5rem; text-align: left; vertical-align: top; border-bottom: 1px solid #e5e5e5; }
    table th { background: #ece9f5; color: #4F5B93; width: 12rem; }

    fieldset { border: 1px solid #ddd; border-radius: 0.3125rem; margin: 1rem 0; padding: 1rem; }
    legend { color: #4F5B93; font-weight: bold; padding: 0 0.3rem; }

    label { display: block; font-size: 0.875rem; font-weight: bold; margin: 0.75rem 0 0.25rem; }
    .field-hint { display: block; font-size: 0.75rem; color: #666; font-weight: normal; margin-top: 0.15rem; }

    input[type="text"], input[type="number"], select {
      width: 100%;
      box-sizing: border-box;
      padding: 0.5rem;
      border: 1px solid #4F5B93;
      border-radius: 0.3125rem;
      font-size: 0.9rem;
      font-family: inherit;
    }

    .checkbox-row { display: flex; align-items: center; gap: 0.5rem; margin: 0.75rem 0; }
    .checkbox-row label { margin: 0; font-weight: normal; }
    .checkbox-row input { width: auto; }

    .status-box {
      padding: 0.75rem 1rem;
      border-radius: 0.3125rem;
      margin: 1rem 0;
      font-weight: bold;
    }

    .status-pass { background: #eaf6ea; color: #1e6b1e; border: 1px solid #b6dfb6; }
    .status-fail { background: #f9e6e6; color: #aa0000; border: 1px solid #e7b6b6; }

    .alert-box {
      background: #f9f9be;
      padding: 0.625rem 1rem;
      border-radius: 0.3125rem;
      margin: 1rem 0;
    }

    #footer {
      color: #666;
      font-size: 0.8rem;
      padding: 0 1.25rem 2.5rem;
      max-width: 50rem;
    }

    .callback-url { font-size: 1rem; word-break: break-all; }
  </style>
</head>
<body>
  <div id="topbar">
    <div class="top-heading"><a href="/">php-oidc Compliance Harness</a></div>
    <div class="top-nav"><a href="https://www.certification.openid.net/">Conformance Suite</a></div>
  </div>
  <div class="container">
    {$bodyHtml}
  </div>
  <div id="footer">
    <p>
      Local debugging tool, not a production application. It shows raw exception messages and
      the full log stream on purpose - see the class docblocks in src/ for why that detail
      normally stays out of anything user-facing. Never deploy this anywhere reachable by
      anyone but you. See <code>compliance/README.md</code>.
    </p>
  </div>
</body>
</html>
HTML;
}

function callbackUrl(): string {
	$host = $_SERVER['HTTP_HOST'] ?? 'localhost';

	return "http://{$host}/index.php?action=callback";
}

/**
 * @param array<string,mixed> $config
 */
function setupForm( array $config ): string {
	$issuer                   = escape($config['issuer'] ?? '');
	$providerUrl              = escape($config['providerUrl'] ?? '');
	$clientId                 = escape($config['clientId'] ?? '');
	$clientSecret             = escape($config['clientSecret'] ?? '');
	$scopes                   = escape($config['scopes'] ?? 'profile email');
	$allowedAlgorithms        = escape($config['allowedAlgorithms'] ?? 'RS256');
	$allowedHosts             = escape($config['allowedHosts'] ?? '');
	$audience                 = escape($config['audience'] ?? '');
	$maxTokenLifetimeSeconds  = escape($config['maxTokenLifetimeSeconds'] ?? '');
	$allowAnyHostChecked      = !empty($config['allowAnyHost']) ? 'checked' : '';
	$allowUntrustedChecked    = !empty($config['allowUntrustedAudiences']) ? 'checked' : '';
	$pkceOptions              = optionsFor([ 'Disabled', 'Optional', 'Required' ], (string)($config['pkce'] ?? 'Disabled'));
	$authMethodOptions        = optionsFor([ 'Basic', 'Post' ], (string)($config['clientAuthMethod'] ?? 'Basic'));
	$callbackUrl              = escape(callbackUrl());

	return <<<HTML
	<h2>1. Register this callback URL with the suite</h2>
	<p>
		When you create a test plan at
		<a href="https://www.certification.openid.net/">certification.openid.net</a> and configure
		a static client, use this as the <code>redirect_uri</code>:
	</p>
	<pre class="callback-url">{$callbackUrl}</pre>

	<h2>2. Point this harness at the plan</h2>
	<form method="post" action="/index.php?action=start">
		<fieldset>
			<legend>Provider</legend>

			<label for="issuer">Issuer</label>
			<input type="text" id="issuer" name="issuer" value="{$issuer}" required
				placeholder="https://www.certification.openid.net/test/a/your-alias">
			<span class="field-hint">From the plan's exported values. Also used to derive discovery when Provider URL is blank.</span>

			<label for="providerUrl">Provider URL (optional)</label>
			<input type="text" id="providerUrl" name="providerUrl" value="{$providerUrl}"
				placeholder="defaults to Issuer">
		</fieldset>

		<fieldset>
			<legend>Client</legend>

			<label for="clientId">Client ID</label>
			<input type="text" id="clientId" name="clientId" value="{$clientId}" required>

			<label for="clientSecret">Client Secret</label>
			<input type="text" id="clientSecret" name="clientSecret" value="{$clientSecret}">
			<span class="field-hint">Leave blank for a public-client test plan.</span>

			<label for="clientAuthMethod">Client authentication method</label>
			<select id="clientAuthMethod" name="clientAuthMethod">{$authMethodOptions}</select>

			<label for="scopes">Scopes</label>
			<input type="text" id="scopes" name="scopes" value="{$scopes}">
			<span class="field-hint">Space or comma separated. "openid" is always added by the library.</span>
		</fieldset>

		<fieldset>
			<legend>Security policy</legend>

			<label for="pkce">PKCE</label>
			<select id="pkce" name="pkce">{$pkceOptions}</select>

			<label for="allowedAlgorithms">Allowed ID token algorithms</label>
			<input type="text" id="allowedAlgorithms" name="allowedAlgorithms" value="{$allowedAlgorithms}">
			<span class="field-hint">Space or comma separated. Defaults to RS256 only.</span>

			<label for="allowedHosts">Allowed endpoint hosts (optional)</label>
			<input type="text" id="allowedHosts" name="allowedHosts" value="{$allowedHosts}">
			<span class="field-hint">Space or comma separated bare hostnames. Blank falls back to the issuer's own host.</span>

			<div class="checkbox-row">
				<input type="checkbox" id="allowAnyHost" name="allowAnyHost" {$allowAnyHostChecked}>
				<label for="allowAnyHost">Allow any host (for a provider that splits endpoints across hosts)</label>
			</div>

			<label for="audience">Expected audience (optional)</label>
			<input type="text" id="audience" name="audience" value="{$audience}">
			<span class="field-hint">Space or comma separated. Blank defaults to just the Client ID.</span>

			<div class="checkbox-row">
				<input type="checkbox" id="allowUntrustedAudiences" name="allowUntrustedAudiences" {$allowUntrustedChecked}>
				<label for="allowUntrustedAudiences">Allow untrusted audiences</label>
			</div>

			<label for="maxTokenLifetimeSeconds">Max token lifetime, seconds (optional)</label>
			<input type="number" id="maxTokenLifetimeSeconds" name="maxTokenLifetimeSeconds" value="{$maxTokenLifetimeSeconds}">
		</fieldset>

		<button type="submit" class="button button-primary">Save &amp; start login</button>
		<a href="/index.php?action=reset" class="button button-secondary">Reset session</a>
		<span class="field-hint">Clears the state/nonce cache and any saved login result - use this between test runs so a stale access token from a finished test can't leak into the next one. Issuer, Client ID, and Client Secret are kept so you do not have to copy them from the plan page again.</span>
	</form>
	HTML;
}

/**
 * Shown after buildAuthorizationCodeRedirect() succeeds, instead of redirecting the browser
 * there automatically. Some conformance test modules (e.g. the discovery-only ones) consider
 * themselves finished the moment they see the discovery request this already triggered, and
 * fail the run if the RP goes on to hit /authorize afterward - an automatic redirect gives the
 * tester no way to stop there. This hands the choice back: click through for an end-to-end
 * test, stop here for a discovery-only one.
 */
function continueToProviderPanel( string $redirectUrl ): string {
	$escapedUrl = escape($redirectUrl);

	return <<<HTML
	<h2>Discovery resolved</h2>
	<p>
		The library fetched the provider's discovery document and built the authorization
		redirect below. Nothing has been sent to the authorization endpoint yet.
	</p>
	<p>
		If this test module only checks discovery, stop here - continuing on will fail it
		with an "Illegal test state change" once it has already finished. Otherwise, continue
		to complete the login.
	</p>
	<pre class="callback-url">{$escapedUrl}</pre>
	<a href="{$escapedUrl}" class="button button-primary">Continue to provider</a>
	<a href="/index.php" class="button button-secondary">Back to harness</a>
	HTML;
}

/**
 * @param list<string> $options
 */
function optionsFor( array $options, string $selected ): string {
	$html = '';

	foreach( $options as $option ) {
		$isSelected = $option === $selected ? ' selected' : '';
		$html .= '<option value="' . escape($option) . '"' . $isSelected . '>' . escape($option) . "</option>\n";
	}

	return $html;
}

/**
 * @param array{idToken:?string,accessToken:?string,refreshToken:?string,expiresIn:?int,claims:array<string,mixed>} $result
 */
function savedResultPanel( array $result ): string {
	$claimsRows = '';

	foreach( $result['claims'] as $key => $value ) {
		$claimsRows .= '<tr><th>' . escape((string)$key) . '</th><td>' . escape(is_scalar($value) ? (string)$value : json_encode($value)) . "</td></tr>\n";
	}

	$accessToken  = escape($result['accessToken'] ?? '(none)');
	$refreshToken = $result['refreshToken'] ?? null;
	$expiresIn    = $result['expiresIn'] ?? null;

	$refreshButton = $refreshToken !== null
		? '<a href="/index.php?action=refresh" class="button button-primary">Refresh token</a>'
		: '<span class="field-hint">No refresh_token was returned - nothing to refresh.</span>';

	return <<<HTML
	<h2>Current session</h2>
	<p>Last successful login on this harness:</p>
	<table>
		<tr><th>access_token</th><td><code>{$accessToken}</code></td></tr>
		<tr><th>expires_in</th><td>{$expiresIn} seconds</td></tr>
		{$claimsRows}
	</table>
	<a href="/index.php?action=userinfo" class="button button-primary">Fetch UserInfo</a>
	{$refreshButton}
	<a href="/index.php?action=reset" class="button button-secondary">Reset session</a>
	HTML;
}

function logPanel( CollectingLogger $logger ): string {
	if( $logger->entries === [] ) {
		return '';
	}

	$lines = '';

	foreach( $logger->entries as $entry ) {
		$printableContext = array_map(static function ( mixed $value ): mixed {
			return $value instanceof \Throwable
				? get_class($value) . ': ' . $value->getMessage()
				: $value;
		}, $entry['context']);

		$context = $printableContext === [] ? '' : ' ' . json_encode($printableContext, JSON_PRETTY_PRINT | JSON_PARTIAL_OUTPUT_ON_ERROR);
		$lines  .= '[' . escape($entry['level']) . '] ' . escape($entry['message']) . escape($context) . "\n";
	}

	return "<h3>What the library logged</h3><pre>{$lines}</pre>";
}

function errorPanel( string $heading, \Throwable $e, CollectingLogger $logger ): string {
	$class   = escape(get_class($e));
	$message = escape($e->getMessage());
	$log     = logPanel($logger);

	return <<<HTML
	<h2>{$heading}</h2>
	<div class="status-box status-fail">FAILED</div>
	<table>
		<tr><th>Exception</th><td><code>{$class}</code></td></tr>
		<tr><th>Message</th><td>{$message}</td></tr>
	</table>
	{$log}
	<p><a href="/index.php" class="button button-secondary">Back to harness</a></p>
	HTML;
}

function successPanel( string $heading, string $idToken, Claims $claims, ?string $accessToken, ?string $refreshToken, ?int $expiresIn, CollectingLogger $logger ): string {
	$claimsRows = '';

	foreach( $claims->all() as $key => $value ) {
		$claimsRows .= '<tr><th>' . escape((string)$key) . '</th><td>' . escape(is_scalar($value) ? (string)$value : json_encode($value)) . "</td></tr>\n";
	}

	$log          = logPanel($logger);
	$accessCell   = escape($accessToken ?? '(none)');
	$refreshCell  = escape($refreshToken ?? '(none)');
	$expiresCell  = $expiresIn === null ? '(not returned)' : escape((string)$expiresIn) . ' seconds';
	$idTokenShort = escape(substr($idToken, 0, 40) . '...');

	return <<<HTML
	<h2>{$heading}</h2>
	<div class="status-box status-pass">PASSED</div>
	<h3>Claims</h3>
	<table>
		{$claimsRows}
	</table>
	<h3>Tokens</h3>
	<table>
		<tr><th>id_token</th><td><code>{$idTokenShort}</code></td></tr>
		<tr><th>access_token</th><td><code>{$accessCell}</code></td></tr>
		<tr><th>refresh_token</th><td><code>{$refreshCell}</code></td></tr>
		<tr><th>expires_in</th><td>{$expiresCell}</td></tr>
	</table>
	{$log}
	<p>
		<a href="/index.php" class="button button-secondary">Back to harness</a>
	</p>
	HTML;
}
