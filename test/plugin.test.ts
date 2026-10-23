import { describe, expect, test } from "bun:test"
import { Credential, Integration } from "@opencode/plugin/effect"
import type { IntegrationEditor, IntegrationMethodRegistration } from "@opencode/plugin/effect/integration"
import type { WebSearchDefinition, WebSearchEditor } from "@opencode/plugin/effect/websearch"
import { Effect } from "effect"
import plugin from "../src/index.js"
import type { Options } from "../src/oauth.js"

const options: Options = {
  provider: "example",
  clientID: "opencode",
  authorizationEndpoint: "https://auth.example/authorize",
  tokenEndpoint: "https://auth.example/token",
  scope: "openid offline_access",
}

type Context = Parameters<typeof plugin.effect>[0]

describe("plugin", () => {
  test("registers one OAuth method for the provider and drops the key method", async () => {
    const updates: IntegrationMethodRegistration[] = []
    const removals: unknown[] = []
    const editor = {
      method: {
        update: (input: IntegrationMethodRegistration) => updates.push(input),
        remove: (integrationID: string, method: unknown) => removals.push([integrationID, method]),
      },
    } as unknown as IntegrationEditor
    const ctx = {
      options,
      integration: {
        transform: (callback: (editor: IntegrationEditor) => void) => {
          callback(editor)
          return Effect.succeed({ dispose: Effect.void })
        },
      },
    }
    await Effect.runPromise(Effect.scoped(plugin.effect(ctx as unknown as Context)))
    expect(updates).toHaveLength(1)
    expect(updates[0]).toMatchObject({ integrationID: "example", method: { id: "oauth", type: "oauth" } })
    expect(removals).toEqual([["example", { type: "key" }]])
  })

  test("does not load with invalid options, and says why", async () => {
    const ctx = { options: { ...options, tokenEndpoint: "http://auth.example/token" } }
    const exit = await Effect.runPromiseExit(Effect.scoped(plugin.effect(ctx as unknown as Context)))
    expect(exit._tag).toBe("Failure")
    expect(String(exit)).toContain("tokenEndpoint must be an https URL")
  })
})

describe("web search", () => {
  // Runs the plugin against a context whose connection resolves to `credential`,
  // and returns what it registered for web search.
  async function registerSearch(input: Options, credential: unknown) {
    const added: WebSearchDefinition[] = []
    let selection: string | false | undefined
    const editor: WebSearchEditor = {
      add: (definition) => added.push(definition),
      default: { get: () => selection, set: (value) => (selection = value) },
    }
    const ctx = {
      options: input,
      integration: {
        transform: () => Effect.succeed({ dispose: Effect.void }),
        connection: {
          active: () => Effect.succeed(credential === undefined ? undefined : { id: "connection" }),
          resolve: () => Effect.succeed(credential),
        },
      },
      websearch: {
        transform: (callback: (editor: WebSearchEditor) => void) => {
          callback(editor)
          return Effect.succeed({ dispose: Effect.void })
        },
      },
    }
    await Effect.runPromise(Effect.scoped(plugin.effect(ctx as unknown as Context)))
    return { added, selection }
  }

  test("searches with the signed-in token, and leaves the default to the config", async () => {
    const authorization: string[] = []
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: (request) => {
        authorization.push(request.headers.get("authorization") ?? "")
        return Response.json({ results: [{ url: "https://example.org/", title: "Example", content: "An example" }] })
      },
    })
    try {
      const credential = Credential.OAuth.make({
        type: "oauth",
        methodID: Integration.MethodID.make("oauth"),
        access: "access-token",
        refresh: "refresh",
        expires: Date.now() + 60_000,
      })
      const { added, selection } = await registerSearch(
        { ...options, searchURL: `http://127.0.0.1:${server.port}/search` },
        credential,
      )

      expect(added.map((definition) => definition.id)).toEqual(["example"])
      expect(selection).toBeUndefined()
      const results = await Effect.runPromise(added[0]!.execute({ query: "example" }))
      expect(results).toEqual([{ url: "https://example.org/", title: "Example", content: "An example", time: {} }])
      expect(authorization).toEqual(["Bearer access-token"])
    } finally {
      server.stop(true)
    }
  })

  test("asks for a sign-in when there is no credential", async () => {
    const { added } = await registerSearch({ ...options, searchURL: "https://search.example/search" }, undefined)
    const error = await Effect.runPromise(Effect.flip(added[0]!.execute({ query: "q" })))
    expect(String(error)).toContain("not signed in: run opencode auth login example")
  })

  test("registers nothing without a searchURL", async () => {
    const { added, selection } = await registerSearch(options, undefined)
    expect(added).toEqual([])
    expect(selection).toBeUndefined()
  })
})
