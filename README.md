# opencode-oauth

An [OpenCode](https://opencode.ai) plugin that signs in to an OpenAI-compatible
model provider with OAuth 2.0, for a provider whose API sits behind your own
identity provider. It can also add web search through a
[SearXNG](https://docs.searxng.org) instance behind the same sign-in.

OpenCode opens the browser for the authorization code grant with PKCE
([RFC 7636](https://www.rfc-editor.org/rfc/rfc7636)) on a loopback redirect
([RFC 8252](https://www.rfc-editor.org/rfc/rfc8252)), stores the tokens, renews
them with the refresh token, and sends the access token to the provider as its
bearer. Nothing in the plugin is specific to one identity provider.

## Requirements

- **OpenCode 2.** The plugin uses the v2 plugin API (`@opencode/plugin` 2.0.32 or
  later); OpenCode 1.x does not load it.
- **An authorization server** (identity provider) with a client that:
  - is public (no client secret) and may use the authorization code grant with
    PKCE (`S256`) and the refresh token grant;
  - allows the redirect URI `http://127.0.0.1:<port>/callback`. A server that
    follows RFC 8252 section 7.3 accepts a loopback redirect on any port, so
    `port` can stay unset; otherwise register a fixed port and set `port` to it;
  - is issued refresh tokens, often by granting it the `offline_access` scope,
    with token responses that include `expires_in`.
- **A provider that accepts the access token** as `Authorization: Bearer …`, such
  as an OpenAI-compatible server behind a gateway that validates the token (for
  example oauth2-proxy with `--skip-jwt-bearer-tokens`).

## Setup

Add the plugin and the provider to your OpenCode config
(`~/.config/opencode/opencode.jsonc`):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "plugins": [
    {
      "package": "opencode-oauth@0.1.0", // x-release-please-version
      "options": {
        "provider": "my-llm",
        "clientID": "opencode",
        "authorizationEndpoint": "https://auth.example.com/oauth2/authorize",
        "tokenEndpoint": "https://auth.example.com/oauth2/token",
        "scope": "openid offline_access"
      }
    }
  ],
  "providers": {
    "my-llm": {
      "name": "My LLM",
      "package": "@opencode/ai/providers/openai-compatible",
      "settings": { "baseURL": "https://llm.example.com/v1" },
      "models": {
        "my-model": { "name": "My model" }
      }
    }
  },
  "model": "my-llm/my-model"
}
```

Then sign in once, with `/connect` in the TUI or `opencode auth login my-llm`.
The browser opens your identity provider, and after you sign in the tab says so.
OpenCode renews the token on its own from then on.

Each plugin entry signs in to one provider, and replaces that provider's API key
method with the sign-in.

### Options

| Option | Required | Description |
|---|---|---|
| `provider` | yes | The key of the provider in `providers` that the plugin signs in to. |
| `clientID` | yes | The client ID registered with the authorization server. |
| `authorizationEndpoint` | yes | The authorization endpoint (`https`). |
| `tokenEndpoint` | yes | The token endpoint (`https`). |
| `scope` | yes | The scopes to request, space-separated. Include what gets you a refresh token. |
| `port` | no | The loopback redirect's port. Unset or `0` lets the OS pick one. |
| `authorizationParams` | no | Extra parameters for the authorization request, such as `{ "audience": "https://llm.example.com" }` for a server that picks the access token's audience from one. It cannot replace the parameters the grant sets itself. |
| `searchURL` | no | A SearXNG search endpoint that accepts the same access token, such as `https://search.example.com/search`. See below. |

Plain `http` is accepted for the endpoints and `searchURL` only on `127.0.0.1` or
`[::1]`.

### Web search through SearXNG

With `searchURL`, the plugin adds a web search provider that sends each query to
that SearXNG with the signed-in access token. Select it in the config:

```jsonc
{
  "websearch": { "provider": "my-llm" }
}
```

The plugin does not make itself the default, so the choice stays in your config.
Without that line, OpenCode asks on its first search, and its "Allow" answer
spreads searches across every web search provider it has.

The SearXNG instance must allow JSON output (`json` in `search.formats` in its
`settings.yml`), and whatever is in front of it must accept the access token.

## What to expect

- **Sign in again** when the refresh token lapses or the server revokes it. A
  failed renewal does not open the browser: run `/connect` or
  `opencode auth login <provider>` again.
- **During a sign-in only**, the plugin listens on `127.0.0.1` for the redirect,
  and closes the listener as soon as the attempt ends. The listener runs in
  OpenCode's server, so sign in where the browser is: an OpenCode server on
  another host (`opencode attach`, SSH) never receives the redirect.
- **Renewals are shared within one OpenCode server**, which every client on the
  machine attaches to. A second server (`--standalone`) refreshing at the same
  moment can spend a refresh token both use, and then both need a new sign-in.
- **A failed search** reaches the model only as "Unable to search the web for
  …": OpenCode keeps the reason, such as a needed sign-in, out of the tool's
  output.

## Security

- Tokens go only to the token endpoint, the provider (sent by OpenCode) and
  `searchURL`. Neither a token request nor a search follows a redirect.
- The redirect listener accepts only the callback carrying this attempt's
  `state`; anything else on the port is refused without ending the sign-in.
- Concurrent renewals of one refresh token share a single request, so a server
  that revokes a reused rotated refresh token does not sign you out.
- Error messages carry an HTTP status and the OAuth error code, never a response
  body.

Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes.

## Development

```sh
bun install
bun run typecheck
bun test
bun run build
```

To try a checkout in OpenCode as npm would install it, run `bun pm pack` and set
the plugin's `package` to `opencode-oauth@file:/absolute/path/to/opencode-oauth-<version>.tgz`.

The tests run on the Bun release that OpenCode compiles in (`packageManager` in
`package.json`). When you bump `@opencode/plugin`, set `effect` to the version it
depends on, since OpenCode hands plugins its own copy, and set `packageManager`
and `@types/bun` to the Bun that OpenCode release uses.

Commits follow [Conventional Commits](https://www.conventionalcommits.org).
[release-please](https://github.com/googleapis/release-please) turns them into a
release pull request; merging it tags the release and publishes it to npm through
trusted publishing, with provenance.

## License

[MIT](LICENSE)
