import { Plugin } from "@opencode/plugin/effect"
import { Effect } from "effect"
import { discoverModels } from "./models.js"
import { parseOptions, registration } from "./oauth.js"
import { search } from "./search.js"

export default Plugin.define({
  id: "opencode-oauth",
  effect: (ctx) =>
    Effect.gen(function* () {
      const options = yield* Effect.sync(() => parseOptions(ctx.options))
      // OpenCode reruns transforms whenever its registry is rebuilt; one
      // registration keeps the discovered metadata across those reruns.
      const method = registration(options)
      yield* ctx.integration.transform((editor) => {
        editor.method.update(method)
        editor.method.remove(options.provider, { type: "key" })
      })
      if (options.discoverModels !== false) yield* discoverModels(ctx, options.provider)
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
