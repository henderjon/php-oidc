<?php

declare(strict_types=1);

/**
 * A minimal auto-submitting HTML form - the mechanism behind OIDC's response_mode=form_post
 * and LTI 1.3's mandatory launch delivery. An OpenID Provider (or LTI Platform) renders this
 * to deliver an authorization response (code/id_token/state) to a Relying Party's redirect_uri
 * via a POST, instead of a 302-with-query-string GET.
 *
 * Auto-submitting is JavaScript's job - there is no plain-HTML way to fire a POST with no user
 * interaction (a <meta http-equiv="refresh"> only ever issues a GET, losing the POST body this
 * exists to carry). The visible "Continue" button below is the fallback for a browser with
 * JavaScript disabled, not decoration - without it, that visitor would have no way to proceed
 * at all.
 *
 * This is a template, not a drop-in include - copy it into your own application and adapt the
 * escaping/templating to whatever it already uses. Variables expected in scope:
 *
 * @var array<string,string|list<string>> $params      Field name => value(s) to submit. A list
 *                                                      value repeats the field name.
 * @var string                            $action      Where to submit the form.
 * @var string                            $method      "POST" or "GET".
 * @var string                            $message     Rendered above the form.
 * @var int                               $submitDelay Seconds to wait before auto-submitting.
 * @var string                            $cspNonce    Nonce for the inline <script> below -
 *                                                      required if your Content-Security-Policy
 *                                                      uses 'strict-dynamic' or a nonce source.
 * @var string|null                       $target      Optional form target (e.g. to submit into
 *                                                      a different window/frame).
 */

assert(isset($cspNonce) && is_string($cspNonce));
assert(!isset($target) || is_string($target));

function escape( string $value ): string {
	return htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
}

echo escape($message);

?>
<form id="auto-submit-form"
	  method="<?= escape($method) ?>"
	  action="<?= escape($action) ?>"
	  <?php if( !empty($target) ) { ?>
		  target="<?= escape($target) ?>"
	  <?php } ?>>
	<?php foreach ($params as $name => $values) {
		foreach ((array)$values as $value) { ?>
	<input type="hidden" name="<?= escape($name) ?>" value="<?= escape($value) ?>" />
	<?php } } ?>
	<input type="submit" value="Continue" />
</form>
<script nonce="<?= escape($cspNonce) ?>">
(function() {
	"use strict";
	setTimeout(function() {
		var form = document.getElementById("auto-submit-form");
		if (!form) {
			throw new Error("Could not get form");
		}
		form.submit();
	}, <?= (1000 * $submitDelay) + 50 ?>);
}());
</script>
<noscript>
<script>document.forms[0].submit();</script>
// Drop it immediately after the </form> tag and the browser submits as soon as it parses that line.
</noscript>
