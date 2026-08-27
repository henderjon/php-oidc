# Compliance harness

A minimal web app that exercises `php-oidc` as a real relying party (RP), so it can be pointed
at the [OpenID Foundation Conformance Suite](https://www.certification.openid.net/) instead of
a mock provider. The `example/` scripts are one-shot CLI scripts that never hold a session
across a redirect - the suite drives a real browser through a real login endpoint, so this
harness exists to be that endpoint.

This is a local debugging tool, not a production application. It shows raw exception messages
and everything the library logs, on purpose - see `AGENTS.md`'s rule against exposing exception
messages to end users, which this deliberately does not follow, because the whole point here is
to see why a test module passed or failed. Never deploy this anywhere reachable by anyone but
you.

## Certification status

As of commit `397108d6113544581f3134c11c69c5df45d4ca00`, these OpenID Foundation RP
certification test plans pass:

- `oidcc-client-basic-certification-test-plan`
- `oidcc-client-config-certification-test-plan`
- `oidcc-client-formpost-basic-certification-test-plan`
- `oidcc-client-formpost-implicit-certification-test-plan`
- `oidcc-client-implicit-certification-test-plan`

Hybrid RP and Dynamic RP are not attempted - see "What this does not cover" below for why.

## Running it

From the repository root:

```sh
composer install
php -S localhost:8080 -t compliance/public
```

Pick any free port - just use the same one consistently while you have a test plan open, since
the callback URL you register with the suite is derived from it.

## Using it against a test plan

1. Go to <https://www.certification.openid.net/>, sign in, and create a new test plan. For this
   library, start with **Basic RP** or **Config RP** - see `local/conformance-suite-howto.txt`
   for why those two are the right starting point. Implicit RP is also reachable via the setup
   form's "Response type" field (step 4 below); Hybrid and Dynamic RP are still out of scope
   entirely.
2. When configuring the plan's client, use a **static client** and set its `redirect_uri` to
   whatever this harness's home page shows under "Register this callback URL with the suite" -
   `http://localhost:<port>/index.php?action=callback`. If the plan's client is
   `application_type: web` and the module uses `response_type=id_token`, that redirect_uri must
   be `https` instead - see "HTTPS for implicit and hybrid flows" below.
3. Copy the plan's exported `issuer` (and `client_id` / `client_secret`, or leave the secret
   blank for a public-client plan) into the harness's setup form at `http://localhost:<port>/`.
4. Match the plan's other settings to the form: response type, PKCE mode, client authentication
   method, allowed ID token algorithms. Leave "Allowed endpoint hosts" and "Allow any host" alone
   unless the specific module you are running needs them.
5. Click **Save & start login**. This redirects your browser to the suite, which acts as the
   fake OP for whichever module is currently active in the plan.
6. After the suite redirects back, the harness shows PASSED (with the returned claims and
   tokens) or FAILED (with the exception and everything the library logged while handling it).
7. If the plan has a UserInfo or refresh_token step, use the **Fetch UserInfo** / **Refresh
   token** buttons on the result page - both reuse the access/refresh token from the last
   completed login in this session.
8. Use **Reset session** between modules that expect a fresh login, or whenever the harness's
   saved state and the plan's own state fall out of sync.

## HTTPS for implicit and hybrid flows

The suite's own redirect_uri validation requires `https` whenever `response_type` is anything
other than plain `code` - but only for a client registered as `application_type: web`, the
default for a plan. `application_type: native` is explicitly exempt (RFC 8252 allows a loopback
redirect over plain `http` for any flow, since there is no network path to intercept it on). If
the plan's client stays `web`, running an Implicit module means this harness needs a real HTTPS
front end.

PHP's built-in dev server has no TLS support at all, so put a local reverse proxy in front of
it. [Caddy](https://caddyserver.com/) does this with no manual certificate handling - it
generates and locally trusts its own certificate automatically. `Caddyfile` and `run.sh` in
this directory already have this wired up:

```
localhost:8443 {
	reverse_proxy localhost:8081
}
```

From `compliance/`, run `./run.sh` (or `caddy run` directly, alongside `php -S localhost:8081
-t public` in another terminal), then register `https://localhost:8443/index.php?action=callback`
as the redirect_uri instead of the plain-http one `php -S` serves directly. `callbackUrl()` in
`src/views.php` builds the callback URL from the request's own Host header, so it follows the
proxied host automatically - no code change needed. Adjust the port numbers in `Caddyfile` and
`run.sh` if you picked something other than 8081 for `php -S`.

## What this does not cover

- Implicit RP: reachable, both `id_token` and `id_token token` response types, both response
  modes. The default response mode (`fragment`) needs JavaScript in the browser to work at all -
  see `fragmentRelayPanel()` in `src/views.php` - since a URL fragment is never sent to any
  server.
- Hybrid RP: not implemented (issue #28 - RFC 9700 deprecates both Implicit and Hybrid, so this
  is intentionally incomplete rather than an oversight).
- Dynamic RP: no dynamic client registration support.
- `client_secret_jwt` / `private_key_jwt` client authentication: not implemented (issue #60).
  The client authentication dropdown here only offers `Basic` and `Post`, matching
  `Oidc\ClientAuthMethod`.

## How it is built

- `public/index.php` - the front controller. Routes on `?action=`: `home`, `start` (POST, saves
  the form and redirects to the suite), `callback`, `userinfo`, `refresh`, `reset`.
- `src/SessionCache.php` - a PSR-16 cache backed by `$_SESSION`. This is the only thing that
  needs to survive the round trip to the suite and back, since php's built-in dev server keeps
  no in-memory state between requests.
- `src/CollectingLogger.php` - a PSR-3 logger that collects entries into an array instead of
  writing them anywhere, so the result page can show exactly what the library logged.
- `src/views.php` - plain functions returning HTML strings. Styled after `local/styleguide.html`
  (topbar, typography, tables, code blocks), recolored to PHP's brand purple - the same
  treatment `docs/index.html` uses - with a small pass/fail status vocabulary added on top for
  the result pages.

No new Composer dependency was added - this reuses the library's own `CurlHttpFetcher` against
the real suite, exactly the way any other consuming application would.
