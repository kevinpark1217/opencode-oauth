import { type Plugin, Provider } from "@opencode/plugin/effect"
import { Effect, Option, Queue, Schema, Stream } from "effect"
import { getJSON } from "./fetch.js"
import { urlProblem } from "./url.js"

const ModelList = Schema.Struct({ data: Schema.Array(Schema.Unknown) })
const isModel = Schema.is(Schema.Struct({ id: Schema.NonEmptyString }))

// The context the server serves: vLLM and SGLang report it as max_model_len, llama.cpp as meta.n_ctx (its
// n_ctx_train is the model's training context).
const ContextSize = Schema.Int.check(Schema.isGreaterThan(0))
const hasMaxModelLen = Schema.is(Schema.Struct({ max_model_len: ContextSize }))
const hasNCtx = Schema.is(Schema.Struct({ meta: Schema.Struct({ n_ctx: ContextSize }) }))
// vLLM and SGLang list a LoRA adapter without one, naming the base model it runs on as its parent.
const isAdapter = Schema.is(Schema.Struct({ parent: Schema.NonEmptyString }))

const contextOf = (model: object) =>
  hasMaxModelLen(model) ? model.max_model_len : hasNCtx(model) ? model.meta.n_ctx : undefined

const listTimeoutMs = 10_000

function listModels(baseURL: string, accessToken: string) {
  return getJSON(new URL(`${baseURL.replace(/\/+$/, "")}/models`), accessToken, "/models", listTimeoutMs).pipe(
    Effect.flatMap((body) =>
      Schema.decodeUnknownEffect(ModelList)(body).pipe(Effect.mapError(() => new Error("/models returned no model list"))),
    ),
    Effect.map(({ data }) => {
      const models = data.filter(isModel)
      const sizes = new Map(models.map((model) => [model.id, contextOf(model)]))
      return models.map((model) => ({
        id: model.id,
        context: sizes.get(model.id) ?? (isAdapter(model) ? sizes.get(model.parent) : undefined),
      }))
    }),
  )
}

type Listed = Effect.Success<ReturnType<typeof listModels>>

export function discoverModels(ctx: Plugin.Context, providerID: string) {
  return Effect.gen(function* () {
    // What was listed for one account at one baseURL; it shows only while both still apply.
    let found: { readonly key: string; readonly baseURL: string; readonly entries: Listed } | undefined
    let listedFor: string | undefined

    // OpenCode applies the config's providers after plugins' provider transforms, so models are added in the model
    // chain. A new model starts from OpenCode's model defaults. The config's model entries apply later in the same
    // chain, field by field, so a model the config lists takes the context too unless its entry sets one.
    yield* ctx.model.transform((models) => {
      if (!found || found.baseURL !== models.provider.get(providerID)?.provider.settings?.baseURL) return
      for (const { id, context } of found.entries)
        models.update(providerID, id, (model) => {
          if (context) model.limit.context = context
        })
    })

    // The signed-in account and the provider's baseURL, once OpenCode has loaded the provider.
    const target = Effect.gen(function* () {
      const connection = yield* ctx.integration.connection.active(providerID)
      if (connection?.type !== "credential") return undefined
      const provider = yield* ctx.provider.get({ providerID: Provider.ID.make(providerID) }).pipe(Effect.option)
      const baseURL = Option.getOrUndefined(provider)?.data.settings?.baseURL
      return typeof baseURL === "string" ? { connection, baseURL, key: `${connection.id} ${baseURL}` } : undefined
    })

    const list = (to: NonNullable<Effect.Success<typeof target>>) =>
      Effect.gen(function* () {
        const problem = urlProblem(to.baseURL)
        if (problem !== undefined) return yield* Effect.fail(new Error(`the provider's baseURL ${problem}`))
        const credential = yield* ctx.integration.connection.resolve(to.connection)
        if (credential?.type !== "oauth") return undefined
        return yield* listModels(to.baseURL, credential.access)
      })

    // Lists once per account and baseURL: at startup, at sign-in or account switch, and when the baseURL changes.
    const refresh = Effect.gen(function* () {
      const to = yield* target
      if (to?.key === listedFor) return
      listedFor = to?.key
      if (found && found.key !== to?.key) {
        found = undefined
        yield* ctx.model.reload()
      }
      if (!to) return
      const entries = yield* list(to).pipe(
        Effect.catch((error) =>
          Effect.logWarning(`model discovery failed: ${error instanceof Error ? error.message : String(error)}`).pipe(
            Effect.as(undefined),
          ),
        ),
      )
      // A change while /models answered has its own refresh queued.
      if (!entries || (yield* target)?.key !== to.key) return
      found = { key: to.key, baseURL: to.baseURL, entries }
      yield* ctx.model.reload()
    })

    const refreshes = yield* Queue.unbounded<void>()
    yield* ctx.event.subscribe({ types: ["credential.switched", "provider.updated"] }).pipe(
      // OpenCode before 2.2 delivers every event, whatever `types` asks for.
      Stream.filter(
        (event) =>
          event.type === "provider.updated" ||
          (event.type === "credential.switched" && event.data.integrationID === providerID),
      ),
      Stream.runForEach(() => Queue.offer(refreshes, undefined)),
      Effect.forkScoped({ startImmediately: true }),
    )
    yield* Queue.offer(refreshes, undefined)
    yield* Stream.fromQueue(refreshes).pipe(Stream.runForEach(() => refresh), Effect.forkScoped)
  })
}
