import { describe, expect, test } from "bun:test"
import { Credential, Integration, Model, Provider } from "@opencode/plugin/effect"
import type { IntegrationEditor, IntegrationMethodRegistration } from "@opencode/plugin/effect/integration"
import type { ModelEditor } from "@opencode/plugin/effect/model"
import type { WebSearchDefinition, WebSearchEditor } from "@opencode/plugin/effect/websearch"
import { Effect, Queue, Stream } from "effect"
import plugin from "../src/index.js"
import type { Options } from "../src/oauth.js"

const options: Options = {
  provider: "example",
  clientID: "opencode",
  authorizationEndpoint: "https://auth.example/authorize",
  tokenEndpoint: "https://auth.example/token",
  scope: "openid offline_access",
  discoverModels: false,
}

type Context = Parameters<typeof plugin.effect>[0]

describe("plugin", () => {
  test("registers one OAuth method for the provider, the same one on every rerun, and drops the key method", async () => {
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
          callback(editor)
          return Effect.succeed({ dispose: Effect.void })
        },
      },
    }
    await Effect.runPromise(Effect.scoped(plugin.effect(ctx as unknown as Context)))
    expect(updates).toHaveLength(2)
    expect(updates[0]).toMatchObject({ integrationID: "example", method: { id: "oauth", type: "oauth" } })
    expect(updates[1]).toBe(updates[0])
    expect(removals).toEqual([
      ["example", { type: "key" }],
      ["example", { type: "key" }],
    ])
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

describe("model discovery", () => {
  const providerID = Provider.ID.make("example")
  const signedIn = (id: string) => ({ type: "credential", id, label: id, method: "oauth" }) as const
  const credential = Credential.OAuth.make({
    type: "oauth",
    methodID: Integration.MethodID.make("oauth"),
    access: "access-token",
    refresh: "refresh",
    expires: Date.now() + 60_000,
  })

  // Runs the plugin against a /models answered by `respond`, with a provider that has one configured model.
  // Like OpenCode, loading or moving the provider rebuilds the models and publishes provider.updated.
  function discover(
    respond: (path: string) => Response | Promise<Response>,
    body: (harness: {
      // Each request also records the models OpenCode showed when it arrived.
      readonly requests: { readonly path: string; readonly authorization: string | null; readonly showing: string[] }[]
      // The signed-in account and the models OpenCode showed after each reload.
      readonly history: { readonly account: string; readonly models: string[] }[]
      readonly models: () => string[]
      readonly added: () => Map<string, Model.Info>
      readonly reloaded: (count: number) => Effect.Effect<void>
      readonly switchTo: (connection: ReturnType<typeof signedIn>) => Effect.Effect<void>
      readonly providerUpdated: () => Effect.Effect<void>
      readonly loadProvider: () => Effect.Effect<void>
      readonly moveProvider: (path: string) => Effect.Effect<void>
    }) => Effect.Effect<void>,
    setup: { readonly providerLoaded?: boolean; readonly baseURL?: string } = {},
  ) {
    const requests: { path: string; authorization: string | null; showing: string[] }[] = []
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      fetch: (request) => {
        const path = new URL(request.url).pathname
        requests.push({ path, authorization: request.headers.get("authorization"), showing: models() })
        return respond(path)
      },
    })
    let providerLoaded = setup.providerLoaded ?? true
    let active = signedIn("first")
    let added = new Map<string, Model.Info>()
    let transform: ((editor: ModelEditor) => void) | undefined
    const history: { account: string; models: string[] }[] = []
    const models = () => ["configured", ...added.keys()]
    const provider = { id: providerID, settings: { baseURL: setup.baseURL ?? `http://127.0.0.1:${server.port}/v1/` } }
    const editor = {
      get: (id: string, model: string) => (id === providerID && model === "configured" ? { id: model } : added.get(model)),
      update: (id: string, model: string, update: (draft: Model.Info) => void) => {
        const draft = structuredClone(Model.Info.default(Provider.ID.make(id), Model.ID.make(model)))
        update(draft)
        added.set(model, draft)
      },
      provider: { get: (id: string) => (providerLoaded && id === providerID ? { provider } : undefined) },
    } as unknown as ModelEditor
    const rebuild = () => {
      added = new Map()
      transform?.(editor)
    }
    return Effect.runPromise(
      Effect.scoped(
        Effect.gen(function* () {
          const events = yield* Queue.unbounded<{ type: string; data: { integrationID?: string } }>()
          const ctx = {
            options: { ...options, discoverModels: undefined },
            integration: {
              transform: () => Effect.succeed({ dispose: Effect.void }),
              connection: { active: () => Effect.sync(() => active), resolve: () => Effect.succeed(credential) },
            },
            provider: {
              get: () =>
                providerLoaded ? Effect.succeed({ data: provider }) : Effect.fail(new Error("Provider not found")),
            },
            model: {
              transform: (callback: (editor: ModelEditor) => void) => {
                transform = callback
                rebuild()
                return Effect.succeed({ dispose: Effect.void })
              },
              reload: () =>
                Effect.sync(() => {
                  rebuild()
                  history.push({ account: active.id, models: models() })
                }),
            },
            event: { subscribe: () => Stream.fromQueue(events) },
          }
          yield* plugin.effect(ctx as unknown as Context)
          const providerUpdated = () => Queue.offer(events, { type: "provider.updated", data: {} })
          yield* body({
            requests,
            history,
            models,
            added: () => added,
            reloaded: (count) =>
              Effect.gen(function* () {
                while (history.length < count) yield* Effect.sleep("5 millis")
              }),
            switchTo: (connection) =>
              Effect.gen(function* () {
                active = connection
                yield* Queue.offer(events, { type: "credential.switched", data: { integrationID: providerID } })
              }),
            providerUpdated,
            loadProvider: () => {
              providerLoaded = true
              rebuild()
              return providerUpdated()
            },
            moveProvider: (path) => {
              provider.settings.baseURL = `http://127.0.0.1:${server.port}${path}`
              rebuild()
              return providerUpdated()
            },
          })
        }),
      ),
    ).finally(() => server.stop(true))
  }

  const listing = (...ids: unknown[]) => Response.json({ object: "list", data: ids })
  const unavailable = () => new Response("unavailable", { status: 503 })

  test("adds the models the config doesn't list, as if the config listed them by ID", () =>
    discover(
      () => listing({ id: "configured" }, { id: "discovered" }, { id: "" }, { name: "no id" }, { id: "discovered" }),
      ({ requests, added, reloaded }) =>
        Effect.gen(function* () {
          yield* reloaded(1)
          expect(requests).toEqual([{ path: "/v1/models", authorization: "Bearer access-token", showing: ["configured"] }])
          expect([...added().entries()]).toEqual([
            ["discovered", Model.Info.default(providerID, Model.ID.make("discovered"))],
          ])
        }),
    ))

  test("loads without waiting for /models", () =>
    discover(
      () => new Promise<Response>(() => {}),
      ({ models }) =>
        Effect.sync(() => {
          expect(models()).toEqual(["configured"])
        }),
    ))

  test("lists the models once OpenCode has loaded the provider", () =>
    discover(
      () => listing({ id: "discovered" }),
      ({ requests, models, reloaded, loadProvider }) =>
        Effect.gen(function* () {
          yield* Effect.sleep("20 millis")
          expect(requests).toEqual([])
          yield* loadProvider()
          yield* reloaded(1)
          expect(models()).toEqual(["configured", "discovered"])
        }),
      { providerLoaded: false },
    ))

  test("lists once per account, however often the providers update", () =>
    discover(
      () => listing({ id: "discovered" }),
      ({ requests, reloaded, switchTo, providerUpdated }) =>
        Effect.gen(function* () {
          yield* reloaded(1)
          yield* providerUpdated()
          yield* providerUpdated()
          yield* switchTo(signedIn("second"))
          yield* reloaded(3)
          expect(requests.map((request) => request.path)).toEqual(["/v1/models", "/v1/models"])
        }),
    ))

  test("never shows one account's models to another", () => {
    let calls = 0
    return discover(
      () => (++calls === 1 ? listing({ id: "discovered" }) : unavailable()),
      ({ requests, models, reloaded, switchTo }) =>
        Effect.gen(function* () {
          yield* reloaded(1)
          expect(models()).toEqual(["configured", "discovered"])
          yield* switchTo(signedIn("second"))
          while (requests.length < 2) yield* Effect.sleep("5 millis")
          expect(requests[1]!.showing).toEqual(["configured"])
          expect(models()).toEqual(["configured"])
        }),
    )
  })

  test("drops a list that arrives after the account switched", () => {
    let release = () => {}
    const held = new Promise<void>((resolve) => (release = resolve))
    let calls = 0
    return discover(
      () => (++calls === 1 ? held.then(() => listing({ id: "first-model" })) : listing({ id: "second-model" })),
      ({ requests, history, models, reloaded, switchTo }) =>
        Effect.gen(function* () {
          while (requests.length < 1) yield* Effect.sleep("5 millis")
          yield* switchTo(signedIn("second"))
          release()
          yield* reloaded(1)
          expect(history.filter((entry) => entry.models.includes("first-model"))).toEqual([])
          expect(models()).toEqual(["configured", "second-model"])
        }),
    )
  })

  test("lists again from a new baseURL, without showing the old one's models", () =>
    discover(
      (path) => listing({ id: path === "/v1/models" ? "old-model" : "new-model" }),
      ({ models, reloaded, moveProvider }) =>
        Effect.gen(function* () {
          yield* reloaded(1)
          expect(models()).toEqual(["configured", "old-model"])
          yield* moveProvider("/v2")
          expect(models()).toEqual(["configured"])
          yield* reloaded(3)
          expect(models()).toEqual(["configured", "new-model"])
        }),
    ))

  test("never sends the token to a plain http provider", async () => {
    const original = globalThis.fetch
    const fetched: string[] = []
    globalThis.fetch = Object.assign(
      (input: string | URL | Request, init?: RequestInit) => {
        fetched.push(String(input instanceof Request ? input.url : input))
        return original(input, init)
      },
      { preconnect: original.preconnect },
    )
    try {
      await discover(
        () => listing({ id: "discovered" }),
        ({ models }) =>
          Effect.gen(function* () {
            yield* Effect.sleep("50 millis")
            expect(fetched).toEqual([])
            expect(models()).toEqual(["configured"])
          }),
        { baseURL: "http://llm.example/v1" },
      )
    } finally {
      globalThis.fetch = original
    }
  })
})
