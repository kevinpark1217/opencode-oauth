# Changelog

## [0.6.0](https://github.com/kevinpark1217/opencode-oauth/compare/v0.5.0...v0.6.0) (2026-11-24)


### ⚠ BREAKING CHANGES

* the plugin needs OpenCode 2.2.1 or later and refuses to load on an older version. After changing a configured issuer, tokenEndpoint or resource, sign in again.
* an issuer, endpoint or searchURL is now refused when it has a user name or password, whitespace, or no host right after the scheme's //, as is an authorization or token endpoint with a fragment and an http endpoint in an https issuer's metadata; models are no longer listed from such a provider baseURL. Fix the URL the error names.
* the plugin no longer loads when its options include one it doesn't know; /plugins names the option, so fix or remove it.
* an authorization response that repeats state, code, error, error_description, or iss when an issuer is expected now fails sign-in (RFC 6749 section 3.1).

### Features

* make scope optional ([#60](https://github.com/kevinpark1217/opencode-oauth/issues/60)) ([1c47ad6](https://github.com/kevinpark1217/opencode-oauth/commit/1c47ad6e774ddbe27bba46913a53e212bd7dac83))


### Bug Fixes

* cap the size of JSON responses ([#61](https://github.com/kevinpark1217/opencode-oauth/issues/61)) ([7429af7](https://github.com/kevinpark1217/opencode-oauth/commit/7429af72b9371b07f4e4aac54d05406e0eb27e9f))
* quote server-supplied text in errors instead of showing it as the whole message ([#55](https://github.com/kevinpark1217/opencode-oauth/issues/55)) ([b879a11](https://github.com/kevinpark1217/opencode-oauth/commit/b879a114ed42ae8254fa449a60bace706339715a))
* read the provider's baseURL the way OpenCode does ([#62](https://github.com/kevinpark1217/opencode-oauth/issues/62)) ([3c59792](https://github.com/kevinpark1217/opencode-oauth/commit/3c59792b1b3cc4b5b3aa6ab45d8e577081fbcfc9))
* record which server issued each credential, and renew only there ([#59](https://github.com/kevinpark1217/opencode-oauth/issues/59)) ([fd07d49](https://github.com/kevinpark1217/opencode-oauth/commit/fd07d49feb9c33600fe64328e7d3a24e8526c778))
* refuse an authorization response that repeats a parameter ([#54](https://github.com/kevinpark1217/opencode-oauth/issues/54)) ([02d3be2](https://github.com/kevinpark1217/opencode-oauth/commit/02d3be26ab273d1c911e76b6804296db8ead718d))
* refuse unknown plugin options ([#56](https://github.com/kevinpark1217/opencode-oauth/issues/56)) ([5c0ad57](https://github.com/kevinpark1217/opencode-oauth/commit/5c0ad57d5f4d830102b89d518cf0b652acc2a430))
* report fetch failures as typed reasons instead of the runtime's error message ([#58](https://github.com/kevinpark1217/opencode-oauth/issues/58)) ([9a00c02](https://github.com/kevinpark1217/opencode-oauth/commit/9a00c028d4fff049c689d49c2c06805115d09c48))
* tighten the URLs the plugin accepts ([#57](https://github.com/kevinpark1217/opencode-oauth/issues/57)) ([35c516b](https://github.com/kevinpark1217/opencode-oauth/commit/35c516ba8b74e9a87e885259d050c81e061256be))

## [0.5.0](https://github.com/kevinpark1217/opencode-oauth/compare/v0.4.0...v0.5.0) (2026-11-20)


### Features

* take each model's context size from /models ([#41](https://github.com/kevinpark1217/opencode-oauth/issues/41)) ([7adfaa1](https://github.com/kevinpark1217/opencode-oauth/commit/7adfaa159281eb12e6d176b9918229f97c9ec4c0))

## [0.4.0](https://github.com/kevinpark1217/opencode-oauth/compare/v0.3.0...v0.4.0) (2026-11-14)


### ⚠ BREAKING CHANGES

* authorizationParams no longer accepts resource; set the resource option instead.

### Features

* send the resource with every token request ([#36](https://github.com/kevinpark1217/opencode-oauth/issues/36)) ([0f68bfe](https://github.com/kevinpark1217/opencode-oauth/commit/0f68bfe9e9bc66755f60602b855f5fa08945c28a))

## [0.3.0](https://github.com/kevinpark1217/opencode-oauth/compare/v0.2.0...v0.3.0) (2026-11-04)


### Features

* add the models the provider's /models lists ([#30](https://github.com/kevinpark1217/opencode-oauth/issues/30)) ([da7207e](https://github.com/kevinpark1217/opencode-oauth/commit/da7207ebc1a3f1f3ec1deb1848d0525b6a1a4ff4))


### Bug Fixes

* stop OpenCode installing unused copies of the plugin API and effect ([#28](https://github.com/kevinpark1217/opencode-oauth/issues/28)) ([77c6813](https://github.com/kevinpark1217/opencode-oauth/commit/77c6813b4382c907d91746143e27683e41842a57))

## [0.2.0](https://github.com/kevinpark1217/opencode-oauth/compare/v0.1.1...v0.2.0) (2026-11-03)


### Features

* discover the authorization server's endpoints from its issuer ([4e8d37e](https://github.com/kevinpark1217/opencode-oauth/commit/4e8d37e956678bea14af0cf00ac7c3e0dd5aa8dd))

## [0.1.1](https://github.com/kevinpark1217/opencode-oauth/compare/v0.1.0...v0.1.1) (2026-11-02)


### Bug Fixes

* accept only token responses that issue a Bearer token ([#16](https://github.com/kevinpark1217/opencode-oauth/issues/16)) ([9e80d43](https://github.com/kevinpark1217/opencode-oauth/commit/9e80d43d8d590c6f443c4dce279ce1a1b127c540))

## 0.1.0 (2026-10-23)

### Features

* Sign in to an OpenAI-compatible provider with OAuth 2.0: the authorization code grant with PKCE on a loopback redirect, renewed with refresh tokens.
* Web search through a SearXNG that accepts the same access token (`searchURL`).
