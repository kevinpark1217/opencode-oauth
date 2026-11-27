import { type Plugin, Provider } from "@opencode/plugin/effect"
import { Effect, Option, Schema } from "effect"
import { readBaseURL } from "./baseurl.js"
import { failedField } from "./errors.js"
import { deadline, explain, fetchJSON } from "./fetch.js"
import type { MetadataCache, MetadataFailure, Server } from "./metadata.js"
import type { Options } from "./options.js"
import { issuerProblem } from "./url.js"

export type PluginContext = Pick<Plugin.Context, "provider" | "storage">

// Where a sign-in goes, and what it asks for.
export interface Target {
  readonly server: Server
  readonly resource: string | undefined
  readonly scope: string | undefined
}

// OAuth 2.0 Protected Resource Metadata (RFC 9728 section 2), with what this client reads.
const ResourceMetadata = Schema.Struct({
  resource: Schema.String,
  authorization_servers: Schema.optional(Schema.Array(Schema.String)),
  scopes_supported: Schema.optional(Schema.Unknown),
  bearer_methods_supported: Schema.optional(Schema.Array(Schema.String)),
  dpop_bound_access_tokens_required: Schema.optional(Schema.Boolean),
})

const resourceTimeoutMs = 10_000

// Most failures are fixed by naming the server yourself. Messages never print the
// server the API names, since a printed value invites pasting it as `issuer`, nor
// the metadata's URL, which is the baseURL with its variables filled in.
const advice = "set issuer to your identity provider's issuer, as its administrator gives it"
const stop = (what: string) => new Error(`${what}; ${advice}`)

const bindingKey = (provider: string) => `binding/${provider}`

// RFC 6749 section 3.3.
const scopeToken = /^[\x21\x23-\x5B\x5D-\x7E]+$/

// The API's scopes, plus offline_access where the identity provider offers it,
// so renewal gets a refresh token.
function defaultScope(listed: unknown, server: Server): Effect.Effect<string | undefined, Error> {
  const scopes = listed === undefined ? [] : listed
  const usable = Array.isArray(scopes) && scopes.every((scope) => typeof scope === "string" && scopeToken.test(scope))
  const unique = usable ? [...new Set(scopes as string[])] : []
  if (!usable || unique.join(" ").length > 2048) {
    return Effect.fail(new Error("the API lists scopes the plugin can't request; set the scope option"))
  }
  if (unique.length === 0) return Effect.succeed(undefined)
  if (server.issuer?.offersOfflineAccess === true && !unique.includes("offline_access")) unique.push("offline_access")
  return Effect.succeed(unique.join(" "))
}

function serverError(failure: MetadataFailure): Error {
  const server = "the authorization server the API names"
  switch (failure.reason) {
    case "fetch":
      return stop(`the metadata of ${server} ${explain(failure.failure)}`)
    case "none":
      return stop(`${server} publishes no metadata`)
    case "invalid":
      return stop(failure.field === undefined ? `${server} has no valid metadata` : `${server} has no valid ${failure.field}`)
    case "another issuer":
      return stop(`${server} has metadata for another issuer`)
    case "endpoint":
      return stop(`the ${failure.name} of ${server} ${failure.problem}`)
    case "no S256":
      return stop(`${server} doesn't list PKCE with S256`)
  }
}

// Plugin storage reports failures as defects. A binding that can't be read, or
// doesn't decode, stops discovery rather than counting as a first sign-in.
function readBinding(host: PluginContext, provider: string): Effect.Effect<string | undefined, Error> {
  const unreadable = stop("the plugin couldn't read which authorization server this provider signed in with before")
  return host.storage.get(bindingKey(provider)).pipe(
    Effect.catchDefect(() => Effect.fail(unreadable)),
    Effect.flatMap((value) =>
      value === undefined || typeof value === "string" ? Effect.succeed(value) : Effect.fail(unreadable),
    ),
  )
}

// A failed write leaves the binding as it was, and the sign-in still completes.
export function storeBinding(host: PluginContext, provider: string, issuer: string | undefined): Effect.Effect<void> {
  const key = bindingKey(provider)
  return (issuer === undefined ? host.storage.remove(key) : host.storage.set(key, issuer)).pipe(
    Effect.catchDefect(() => Effect.logWarning("couldn't store which authorization server this provider signed in with")),
  )
}

// Finds the authorization server from the API's protected resource metadata (RFC 9728).
export function discover(host: PluginContext, options: Options, servers: MetadataCache): Effect.Effect<Target, Error> {
  return Effect.gen(function* () {
    const provider = yield* host.provider.get({ providerID: Provider.ID.make(options.provider) }).pipe(Effect.option)
    if (Option.isNone(provider)) return yield* Effect.fail(new Error(`no provider named ${options.provider} is configured`))
    const read = readBaseURL(provider.value.data.settings)
    if (read === undefined) return yield* Effect.fail(stop("the provider has no baseURL to find the authorization server from"))
    if ("problem" in read) return yield* Effect.fail(stop(read.problem))
    // RFC 9728 section 1.2 and RFC 8707 section 2.
    const identifier = read.url
    if (/[?#]/.test(identifier)) {
      return yield* Effect.fail(stop("the provider's baseURL has a query or fragment, so it can't name the API as a resource"))
    }

    // RFC 9728 section 3.1: the well-known path goes between the host and the path.
    const url = new URL(identifier)
    const location = `${url.origin}/.well-known/oauth-protected-resource${url.pathname === "/" ? "" : url.pathname}`
    const body = yield* fetchJSON(location, { headers: { Accept: "application/json" } }, deadline(resourceTimeoutMs)).pipe(
      Effect.mapError((failure) => stop(`the API's resource metadata ${explain(failure)}`)),
    )
    const document = yield* Schema.decodeUnknownEffect(ResourceMetadata)(body).pipe(
      Effect.mapError((error) => {
        const field = failedField(error.issue, Object.keys(ResourceMetadata.fields))
        return stop(field === undefined ? "the API has no valid resource metadata" : `the API's resource metadata has no valid ${field}`)
      }),
    )
    // Sections 3.3 and 6: compared as strings, so a document can't speak for another API.
    if (document.resource !== identifier) return yield* Effect.fail(stop("the API's resource metadata describes another resource"))
    if (document.dpop_bound_access_tokens_required === true) {
      return yield* Effect.fail(new Error("the API requires DPoP-bound access tokens, which OpenCode can't send"))
    }
    // Section 2: an empty list means no bearer method; an omitted one says nothing.
    const methods = document.bearer_methods_supported
    if (methods !== undefined && !methods.includes("header")) {
      return yield* Effect.fail(
        new Error("the API doesn't accept the access token in the Authorization header, the only way OpenCode sends it"),
      )
    }
    const named = [...new Set(document.authorization_servers ?? [])]
    if (named.length !== 1) {
      return yield* Effect.fail(stop(`the API names ${named.length === 0 ? "no" : "more than one"} authorization server`))
    }
    const issuer = named[0]!

    // Bound to the provider's last completed sign-in, and compared before the named server is contacted.
    const bound = yield* readBinding(host, options.provider)
    if (bound !== undefined && bound !== issuer) {
      return yield* Effect.fail(
        new Error(
          `the API now names a different authorization server than this provider signed in with before; if that's expected, ${advice}`,
        ),
      )
    }
    if (issuerProblem(issuer, location) !== undefined) {
      return yield* Effect.fail(stop("the API names an authorization server whose issuer the plugin can't use"))
    }
    const server = yield* servers.fresh(issuer).pipe(Effect.mapError(serverError))
    // RFC 9207 is required here, not only used when offered: the flag comes from the server the API named, and
    // accepting its absence would let a real provider's response without `iss` through (RFC 9700 section 4.4.2.1).
    if (server.issuer?.inResponse !== true) {
      return yield* Effect.fail(stop("the authorization server the API names doesn't put its issuer in responses (RFC 9207)"))
    }
    if (!server.issuer.listsS256) return yield* Effect.fail(serverError({ reason: "no S256" }))
    const scope = options.scope ?? (yield* defaultScope(document.scopes_supported, server))
    // RFC 9728 section 7.4: a token meant for this API shouldn't work at others.
    return { server, resource: options.resource ?? identifier, scope }
  })
}
