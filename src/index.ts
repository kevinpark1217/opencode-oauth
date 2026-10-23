// OpenCode signs in to one model provider over OAuth 2.0, stores the credential,
// and sends its access token as the provider's bearer. With `searchURL`, web
// search goes through a SearXNG with the same token.
import { Plugin } from "@opencode/plugin/effect"
import { Effect } from "effect"
import { parseOptions, registration } from "./oauth.js"
import { search } from "./search.js"

export type { Options } from "./oauth.js"

export default Plugin.define({
  id: "opencode-oauth",
  effect: (ctx) =>
    Effect.gen(function* () {
      const options = yield* Effect.sync(() => parseOptions(ctx.options))
      yield* ctx.integration.transform((editor) => {
        editor.method.update(registration(options))
        // The provider takes these tokens, not an API key.
        editor.method.remove(options.provider, { type: "key" })
      })
      const searchURL = options.searchURL
      if (searchURL === undefined) return
      // Not made the default: a plugin's choice would hide the one the user makes
      // in OpenCode, so the config's `websearch` selects it.
      yield* ctx.websearch.transform((editor) => {
        editor.add({
          id: options.provider,
          name: "SearXNG",
          execute: ({ query }) =>
            Effect.gen(function* () {
              // resolve() renews a token that is about to expire.
              const connection = yield* ctx.integration.connection.active(options.provider)
              const credential = connection && (yield* ctx.integration.connection.resolve(connection))
              if (credential?.type !== "oauth") {
                return yield* Effect.fail(new Error(`not signed in: run opencode auth login ${options.provider}`))
              }
              return yield* search(searchURL, query, credential.access)
            }),
        })
      })
    }),
})
