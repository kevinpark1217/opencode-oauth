# Contributing

These rules apply to people and coding agents alike.

opencode-oauth is an OpenCode 2 plugin: OAuth 2.0 sign-in (authorization code with PKCE on a loopback redirect) for an OpenAI-compatible provider, plus optional SearXNG web search. Code is in `src/`, tests in `test/`.

```sh
bun install
bun run typecheck
bun test
```

## Rules

- **Comments and docs:** none by default. Add one only when it says something the code can't, such as why it's done this way or what a spec requires.
- **Tests:** add one only when it would catch a real bug or security issue, and check that it fails without your change.
- **Writing:** for humans. Keep it short, plain and self-contained, so readers don't have to follow links or piece things together from several places.
- **Versions in docs:** don't write a release number; use `@latest` or `<version>`.
- **OAuth:** follow the specs (RFC 6749, 6750, 7636, 8252, 9700) and fix problems properly rather than patching around them. Never put tokens, codes or response bodies in errors or logs.
- **No AI attribution:** no co-author trailers, "generated with" lines or mentions of AI tools in commits, pull requests, issues or code.
- **Commits:** [Conventional Commits](https://www.conventionalcommits.org); releases are built from them. Don't edit versions or `CHANGELOG.md` by hand.
- **Review:** every change goes through a pull request with passing CI. Before asking for review, have the change reviewed from a fresh context (a different model, if you use one) and address what it finds.
