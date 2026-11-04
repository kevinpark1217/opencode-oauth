import type { Plugin } from "@opencode/plugin/effect"
import { Effect, Queue, Schema, Stream } from "effect"
import { getJSON } from "./fetch.js"
import { secure } from "./oauth.js"

const ModelList = Schema.Struct({ data: Schema.Array(Schema.Unknown) })
const isModel = Schema.is(Schema.Struct({ id: Schema.NonEmptyString }))

const listTimeoutMs = 10_000

export function listModels(baseURL: string, accessToken: string) {
  return getJSON(new URL(`${baseURL.replace(/\/+$/, "")}/models`), accessToken, "/models", listTimeoutMs).pipe(
    Effect.flatMap((body) =>
      Schema.decodeUnknownEffect(ModelList)(body).pipe(Effect.mapError(() => new Error("/models returned no model list"))),
    ),
    Effect.map(({ data }) => data.filter(isModel).map((model) => model.id)),
  )
}

type Connection = NonNullable<Effect.Success<ReturnType<Plugin.Context["integration"]["connection"]["active"]>>>

export function discoverModels(ctx: Plugin.Context, providerID: string) {
  return Effect.gen(function* () {
    let baseURL: string | undefined
    let found: { readonly credentialID: string; readonly baseURL: string; readonly ids: readonly string[] } | undefined
    const refreshes = yield* Queue.unbounded<void>()

    // A provider from the user's config joins OpenCode's provider chain after plugins, so this reads and adds
    // models here. A new model starts as if the config listed it by ID; one the config lists exists and stays as is.
    yield* ctx.model.transform((models) => {
      const url = models.provider.get(providerID)?.provider.settings?.baseURL
      if (typeof url === "string" && url !== baseURL) {
        baseURL = url
        Queue.offerUnsafe(refreshes, undefined)
      }
      for (const id of found?.ids ?? []) if (!models.get(providerID, id)) models.update(providerID, id, () => {})
    })

    const list = (connection: Connection | undefined, url: string | undefined) =>
      Effect.gen(function* () {
        if (connection?.type !== "credential" || url === undefined) return undefined
        const credential = yield* ctx.integration.connection.resolve(connection)
        if (credential?.type !== "oauth") return undefined
        if (!secure(url)) return yield* Effect.fail(new Error("the provider's baseURL must be an https URL"))
        return { credentialID: connection.id, baseURL: url, ids: yield* listModels(url, credential.access) }
      })

    const refresh = Effect.gen(function* () {
      const connection = yield* ctx.integration.connection.active(providerID)
      const url = baseURL
      // Another account or provider never sees this list, even while its own loads or fails to.
      if (found && (connection?.type !== "credential" || connection.id !== found.credentialID || url !== found.baseURL)) {
        found = undefined
        yield* ctx.model.reload()
      }
      const kept = found
      found = yield* list(connection, url).pipe(
        Effect.catch((error) =>
          Effect.logWarning(`model discovery failed: ${error instanceof Error ? error.message : String(error)}`).pipe(
            Effect.as(kept),
          ),
        ),
      )
      yield* ctx.model.reload()
    })

    yield* ctx.event.subscribe({ types: ["credential.switched"] }).pipe(
      Stream.filter((event) => event.data.integrationID === providerID),
      Stream.runForEach(() => Queue.offer(refreshes, undefined)),
      Effect.forkScoped({ startImmediately: true }),
    )
    yield* Stream.fromQueue(refreshes).pipe(Stream.runForEach(() => refresh), Effect.forkScoped)
  })
}
