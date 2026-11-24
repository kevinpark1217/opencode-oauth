import { Effect, Schema } from "effect"
import { failedField, quotable, toError } from "./errors.js"
import { deadline, explain, type Failure, fetchJSON } from "./fetch.js"
import { endpointProblem } from "./url.js"

// Authorization server metadata (RFC 8414 section 2, OpenID Connect Discovery
// section 3), with what this client needs of it.
const Metadata = Schema.Struct({
  issuer: Schema.NonEmptyString,
  authorization_endpoint: Schema.NonEmptyString,
  token_endpoint: Schema.NonEmptyString,
  code_challenge_methods_supported: Schema.optional(Schema.Array(Schema.String)),
  authorization_response_iss_parameter_supported: Schema.optional(Schema.Boolean),
})

export interface Server {
  readonly authorizationEndpoint: string
  readonly tokenEndpoint: string
  // Known only from an issuer's metadata; then authorization responses are checked against it.
  readonly issuer?: { readonly id: string; readonly inResponse: boolean }
}

const metadataTimeoutMs = 10_000

// OpenID Connect Discovery appends the well-known path to the issuer; RFC 8414
// inserts it between the host and the issuer's path.
function metadataLocations(issuer: string) {
  const url = new URL(issuer)
  const path = url.pathname.replace(/\/$/, "")
  return [`${url.origin}${path}/.well-known/openid-configuration`, `${url.origin}/.well-known/oauth-authorization-server${path}`]
}

type LookupFailure =
  | { readonly reason: "fetch"; readonly location: string; readonly failure: Failure }
  | { readonly reason: "none" }
  | { readonly reason: "invalid"; readonly location: string; readonly field: string | undefined }
  | { readonly reason: "another issuer"; readonly named: string }

function lookup(issuer: string): Effect.Effect<{ location: string; metadata: typeof Metadata.Type }, LookupFailure> {
  return Effect.gen(function* () {
    const within = deadline(metadataTimeoutMs)
    for (const location of metadataLocations(issuer)) {
      const body = yield* fetchJSON(location, { headers: { Accept: "application/json" } }, within).pipe(
        Effect.catchIf((failure) => failure.reason === "status" && failure.status === 404, () => Effect.succeed(undefined)),
        Effect.mapError((failure): LookupFailure => ({ reason: "fetch", location, failure })),
      )
      if (body === undefined) continue
      const metadata = yield* Schema.decodeUnknownEffect(Metadata)(body).pipe(
        Effect.mapError(
          (error): LookupFailure => ({ reason: "invalid", location, field: failedField(error.issue, Object.keys(Metadata.fields)) }),
        ),
      )
      // RFC 8414 section 3.3, OpenID Connect Discovery section 4.3.
      if (metadata.issuer !== issuer) return yield* Effect.fail<LookupFailure>({ reason: "another issuer", named: metadata.issuer })
      return { location, metadata }
    }
    return yield* Effect.fail<LookupFailure>({ reason: "none" })
  })
}

// A configured issuer is the user's own, so its location and value are named.
function lookupError(issuer: string, failure: LookupFailure): Error {
  switch (failure.reason) {
    case "fetch":
      // The budget spans both locations, so a timeout belongs to the issuer.
      return new Error(
        `authorization server metadata ${failure.failure.reason === "timeout" ? `for ${issuer}` : `at ${failure.location}`} ` +
          explain(failure.failure),
      )
    case "none":
      return new Error(`no authorization server metadata for ${issuer}`)
    case "invalid":
      return new Error(
        failure.field === undefined
          ? `${failure.location} returned no authorization server metadata`
          : `authorization server metadata has no valid ${failure.field}`,
      )
    case "another issuer": {
      const named = quotable(failure.named, 256) ? `"${failure.named}"` : "a different issuer"
      return new Error(`authorization server metadata names ${named}, not "${issuer}"`)
    }
  }
}

function serverMetadata(issuer: string) {
  return Effect.gen(function* () {
    const { location, metadata } = yield* lookup(issuer).pipe(Effect.mapError((failure) => lookupError(issuer, failure)))
    for (const [name, value] of [
      ["authorization_endpoint", metadata.authorization_endpoint],
      ["token_endpoint", metadata.token_endpoint],
    ] as const) {
      const problem = endpointProblem(value, location)
      if (problem !== undefined) return yield* Effect.fail(new Error(`authorization server metadata's ${name} ${problem}`))
    }
    const methods = metadata.code_challenge_methods_supported
    if (methods !== undefined && !methods.includes("S256")) {
      return yield* Effect.fail(new Error("authorization server does not support PKCE with S256"))
    }
    return {
      authorizationEndpoint: metadata.authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      issuer: { id: issuer, inResponse: metadata.authorization_response_iss_parameter_supported === true },
    } satisfies Server
  })
}

export type MetadataCache = (issuer: string) => Effect.Effect<Server, Error>

// Metadata is fetched when first needed, not at startup, and kept per issuer once
// it is valid; a failure is retried on the next attempt.
export function metadataCache(): MetadataCache {
  const pending = new Map<string, Promise<Server>>()
  return (issuer) =>
    Effect.tryPromise({
      try: () => {
        const known = pending.get(issuer)
        if (known !== undefined) return known
        const found = Effect.runPromise(serverMetadata(issuer)).catch((error: unknown) => {
          pending.delete(issuer)
          throw error
        })
        pending.set(issuer, found)
        return found
      },
      catch: toError,
    })
}
