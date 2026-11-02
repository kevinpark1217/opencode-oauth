# Contributing

These rules apply to people and coding agents alike.

opencode-oauth is an OpenCode 2 plugin: OAuth 2.0 sign-in (authorization code with PKCE on a loopback redirect) for an OpenAI-compatible provider, plus optional SearXNG web search. Code is in `src/`, tests in `test/`, user documentation in `README.md`.

```sh
bun install
bun run typecheck
bun test
bun pm pack --dry-run   # builds and checks the package, as CI does
```

To try a checkout in OpenCode, run `bun pm pack` and set the plugin's `package` to `opencode-oauth@file:/absolute/path/to/opencode-oauth-<version>.tgz`.

## Rules

- **Responsibility:** a person must understand and answer for every change. Agents open an issue or pull request only when a person asks for that one.
- **Comments:** none by default. Add one only when it says something the code can't, such as why it's done this way or what a spec requires.
- **Docs:** update `README.md` when behavior, options or requirements change. Don't add other doc files, and don't write a release number in docs; use `@latest` or `<version>`.
- **Tests:** add one only when it would catch a real bug or security issue, and check that it fails without your change.
- **Writing:** for humans, so short, plain and self-contained.
- **OAuth:** follow the specs (RFC 6749, 6750, 7636, 8252, 9700) and fix problems properly rather than patching around them. Never put tokens, codes or response bodies in errors or logs.
- **Dependencies:** OpenCode hands plugins its own `effect` and runs them on its own Bun, so `@opencode/plugin`, `effect`, `@types/bun` and `packageManager` move together: `effect` to the version `@opencode/plugin` depends on, Bun to the one that OpenCode release compiles in. Don't bump one alone. Raise the `@opencode/plugin` peer range in `package.json`, and the minimum in README's Requirements, only when the code needs a newer plugin API.
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org). Pull requests are squash-merged, so the PR title (or a lone commit's title) becomes the commit that releases are built from. Before 1.0, a breaking change (`feat!`) bumps the minor version. No AI co-author trailers or "generated with" footers.
- **Review:** every change goes through a pull request with passing CI. Before asking for review, have it reviewed by someone who hasn't seen the work (for an agent, a fresh session, ideally on a different model), and address what it finds.

## Releases

release-please opens a release pull request from the commits; don't edit versions or `CHANGELOG.md` by hand. Merging it tags the release and stages it on npm through trusted publishing, with provenance (no npm token). The version can't be installed until a maintainer approves it with 2FA, on npmjs.com or with `npm stage approve <stage-id>` (`npm stage list opencode-oauth` shows the ID). A rejected version needs a new number.
