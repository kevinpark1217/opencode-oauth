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
  // Unvalidated, so a malformed list can't break a configured issuer; it only counts as not offering offline_access.
  scopes_supported: Schema.optional(Schema.Unknown),
})

export interface Server {
  readonly authorizationEndpoint: string
  readonly tokenEndpoint: string
  // Known only from an issuer's metadata; then authorization responses are checked against it.
  readonly issuer?: {
    readonly id: string
    readonly inResponse: boolean
    readonly listsS256: boolean
    readonly offersOfflineAccess: boolean
  }
}

const metadataTimeoutMs = 10_000

// OpenID Connect Discovery appends the well-known path to the issuer; RFC 8414
// inserts it between the host and the issuer's path.
function metadataLocations(issuer: string) {
  const url = new URL(issuer)
  const path = url.pathname.replace(/\/$/, "")
  return [`${url.origin}${path}/.well-known/openid-configuration`, `${url.origin}/.well-known/oauth-authorization-server${path}`]
}

export type MetadataFailure =
  | { readonly reason: "fetch"; readonly location: string; readonly failure: Failure }
  | { readonly reason: "none" }
  | { readonly reason: "invalid"; readonly location: string; readonly field: string | undefined }
  | { readonly reason: "another issuer"; readonly named: string }
  | { readonly reason: "endpoint"; readonly name: string; readonly problem: string }
  | { readonly reason: "no S256" }

function lookup(issuer: string): Effect.Effect<{ location: string; metadata: typeof Metadata.Type }, MetadataFailure> {
  return Effect.gen(function* () {
    const within = deadline(metadataTimeoutMs)
    for (const location of metadataLocations(issuer)) {
      const body = yield* fetchJSON(location, { headers: { Accept: "application/json" } }, within).pipe(
        Effect.catchIf((failure) => failure.reason === "status" && failure.status === 404, () => Effect.succeed(undefined)),
        Effect.mapError((failure): MetadataFailure => ({ reason: "fetch", location, failure })),
      )
      if (body === undefined) continue
      const metadata = yield* Schema.decodeUnknownEffect(Metadata)(body).pipe(
        Effect.mapError(
          (error): MetadataFailure => ({ reason: "invalid", location, field: failedField(error.issue, Object.keys(Metadata.fields)) }),
        ),
      )
      // RFC 8414 section 3.3, OpenID Connect Discovery section 4.3.
      if (metadata.issuer !== issuer) return yield* Effect.fail<MetadataFailure>({ reason: "another issuer", named: metadata.issuer })
      return { location, metadata }
    }
    return yield* Effect.fail<MetadataFailure>({ reason: "none" })
  })
}

// A configured or recorded issuer is the user's own, so its location and value are named.
function metadataError(issuer: string, failure: MetadataFailure): Error {
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
    case "endpoint":
      return new Error(`authorization server metadata's ${failure.name} ${failure.problem}`)
    case "no S256":
      return new Error("authorization server does not support PKCE with S256")
  }
}

function serverMetadata(issuer: string): Effect.Effect<Server, MetadataFailure> {
  return Effect.gen(function* () {
    const { location, metadata } = yield* lookup(issuer)
    for (const [name, value] of [
      ["authorization_endpoint", metadata.authorization_endpoint],
      ["token_endpoint", metadata.token_endpoint],
    ] as const) {
      const problem = endpointProblem(value, location)
      if (problem !== undefined) return yield* Effect.fail<MetadataFailure>({ reason: "endpoint", name, problem })
    }
    // RFC 8414 section 2: an omitted list means no PKCE, but a configured issuer is given the benefit of the doubt.
    const methods = metadata.code_challenge_methods_supported
    if (methods !== undefined && !methods.includes("S256")) return yield* Effect.fail<MetadataFailure>({ reason: "no S256" })
    return {
      authorizationEndpoint: metadata.authorization_endpoint,
      tokenEndpoint: metadata.token_endpoint,
      issuer: {
        id: issuer,
        inResponse: metadata.authorization_response_iss_parameter_supported === true,
        listsS256: methods?.includes("S256") === true,
        offersOfflineAccess: Schema.is(Schema.Array(Schema.String))(metadata.scopes_supported) &&
          metadata.scopes_supported.includes("offline_access"),
      },
    }
  })
}

export interface MetadataCache {
  // Fetched when first needed, not at startup, and kept once it is valid; a failure is retried next time.
  readonly get: (issuer: string) => Effect.Effect<Server, Error>
  // Fetched afresh, replacing what is kept, so a sign-in sees the server as it is now.
  readonly fresh: (issuer: string) => Effect.Effect<Server, MetadataFailure>
}

export function metadataCache(): MetadataCache {
  const kept = new Map<string, Promise<Server>>()
  return {
    get: (issuer) =>
      Effect.tryPromise({
        try: () => {
          const known = kept.get(issuer)
          if (known !== undefined) return known
          const found = Effect.runPromise(
            serverMetadata(issuer).pipe(Effect.mapError((failure) => metadataError(issuer, failure))),
          ).catch((error: unknown) => {
            // A fresh lookup may have replaced this one meanwhile.
            if (kept.get(issuer) === found) kept.delete(issuer)
            throw error
          })
          kept.set(issuer, found)
          return found
        },
        catch: toError,
      }),
    fresh: (issuer) =>
      serverMetadata(issuer).pipe(Effect.tap((server) => Effect.sync(() => kept.set(issuer, Promise.resolve(server))))),
  }
}
