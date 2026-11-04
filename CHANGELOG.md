# Changelog

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
