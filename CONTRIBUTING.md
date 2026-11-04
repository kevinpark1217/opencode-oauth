# Contributing

opencode-oauth is an OpenCode 2 plugin: OAuth 2.0 sign-in (authorization code with PKCE on a loopback redirect) for an OpenAI-compatible provider, plus optional SearXNG web search. Code is in `src/`, tests in `test/`, user documentation in `README.md`.

## Reporting a bug or asking for a feature

Open an issue with the matching form. Report security vulnerabilities privately, as [SECURITY.md](SECURITY.md) describes.

## Setting up

```sh
bun install
bun run typecheck
bun test
bun pm pack --dry-run   # builds and checks the package, as CI does
```

To try a checkout in OpenCode, run `bun pm pack` and set the plugin's `package` to `opencode-oauth@file:/absolute/path/to/opencode-oauth-<version>.tgz`.

## Making a change

- Fix the cause, not the symptom. OAuth code follows the specs (RFC 6749, 6750, 7636, 8252, 9700), and tokens, codes and response bodies never go into errors or logs.
- Add a test only when it would catch a real bug or security issue, and check that it fails without your change.
- Add a comment only when it says something the code can't, such as why it's done this way or what a spec requires.
- Update `README.md` when behavior, options or requirements change. Don't add other doc files.
- Don't write anything that stays correct only if someone remembers to update it, such as a release number in the docs; use `@latest` or `<version>`.
- Write docs, comments and pull requests for people: short, plain and self-contained.

## Updating dependencies

OpenCode hands plugins its own `effect` and runs them on its own Bun, so `@opencode/plugin`, `effect`, `@types/bun` and `packageManager` move together: `effect` and `@types/bun` to the versions `@opencode/plugin` uses, and Bun to that OpenCode release's `packageManager`. Renovate's "OpenCode host" pull request does this for each OpenCode release. Raise the `@opencode/plugin` peer range in `package.json`, and the minimum in README's Requirements, only when the code needs a newer plugin API.

## Opening a pull request

Every change goes through a pull request, and CI must pass. Keep each one to a single change, and fill in the template.

Pull requests are squash-merged, so the PR title (or a lone commit's title) becomes the commit that releases are built from. Write it as a [Conventional Commit](https://www.conventionalcommits.org). Before 1.0, a breaking change (`feat!`) bumps the minor version.

## Using AI

AI tools are allowed, but you must understand and answer for every line. Say in the pull request description which AI tools you used and what they did, or that you used none. Don't credit them in commits: no co-author trailers or "generated with" footers.

## Releasing

release-please opens a release pull request from the commits; don't edit versions or `CHANGELOG.md` by hand. Merging it tags the release and stages it on npm through trusted publishing, with provenance (no npm token). The version can't be installed until a maintainer approves it with 2FA, on npmjs.com or with `npm stage approve <stage-id>` (`npm stage list opencode-oauth` shows the ID). A rejected version needs a new number.
