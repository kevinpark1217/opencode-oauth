import { Credential, Integration } from "@opencode/plugin/effect"
import type {
  IntegrationOAuthAuthorization,
  IntegrationOAuthMethodRegistration,
} from "@opencode/plugin/effect/integration"
import { Deferred, Effect, Option, Schema, SchemaTransformation, type Scope } from "effect"
import { createServer, type ServerResponse } from "node:http"
import { failedField, quotable, toError } from "./errors.js"
import { deadline, explain, fetchJSON } from "./fetch.js"
import { type MetadataCache, metadataCache, type Server } from "./metadata.js"
import type { Options } from "./options.js"
import { endpointProblem, issuerProblem, resourceProblem } from "./url.js"

// expires_in is digits (RFC 6749 appendix A.14); some servers send them as a
// JSON string.
const DigitsAsNumber = Schema.String.check(Schema.isPattern(/^\d+$/)).pipe(
  Schema.decodeTo(Schema.Finite, SchemaTransformation.numberFromString),
)

// RFC 6749 section 5.1. expires_in is optional there, but OpenCode renews by it.
// Some servers send refresh_token: null for none.
const TokenResponse = Schema.Struct({
  access_token: Schema.NonEmptyString,
  token_type: Schema.NonEmptyString,
  expires_in: Schema.Union([Schema.Finite, DigitsAsNumber]).check(Schema.isGreaterThan(0)),
  refresh_token: Schema.optional(Schema.NullOr(Schema.NonEmptyString)),
})

const methodID = Integration.MethodID.make("oauth")
const callbackPath = "/callback"
// Ends a hung token request, and with it a renewal OpenCode stopped waiting for.
const tokenRequestTimeoutMs = 30_000

const base64url = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url")
const randomToken = () => base64url(crypto.getRandomValues(new Uint8Array(32)))

const reply = (response: ServerResponse, status: number, text: string) =>
  response
    .writeHead(status, {
      "Content-Type": "text/plain; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store",
    })
    .end(text)

type Client = Pick<Options, "clientID" | "resource">

function signInServer(options: Options, servers: MetadataCache): Effect.Effect<Server, Error> {
  const { issuer, authorizationEndpoint, tokenEndpoint } = options
  if (issuer !== undefined) return servers(issuer)
  if (authorizationEndpoint === undefined || tokenEndpoint === undefined) {
    return Effect.fail(new Error("set issuer, or both authorizationEndpoint and tokenEndpoint"))
  }
  return Effect.succeed({ authorizationEndpoint, tokenEndpoint })
}

// Renewal goes only to the server that issued a credential (RFC 6749 section
// 10.4), for the resource it was granted for, so the credential's metadata keeps
// both. Fields this release doesn't know are kept as stored.
const recordKey = "opencode-oauth"
const IssuedBy = Schema.Struct({
  issuer: Schema.optional(Schema.String),
  tokenEndpoint: Schema.optional(Schema.String),
  resource: Schema.optional(Schema.String),
})
type IssuedBy = typeof IssuedBy.Type

const issuedBy = ({ issuer, tokenEndpoint, resource }: Options): IssuedBy => ({
  ...(issuer !== undefined ? { issuer } : { tokenEndpoint }),
  ...(resource !== undefined ? { resource } : {}),
})

// The one server a record names, if it passes the checks a configured one gets.
function serverIn({ issuer, tokenEndpoint, resource }: IssuedBy) {
  if (resource !== undefined && resourceProblem(resource) !== undefined) return undefined
  if (issuer !== undefined) return tokenEndpoint === undefined && issuerProblem(issuer) === undefined ? { issuer } : undefined
  return tokenEndpoint !== undefined && endpointProblem(tokenEndpoint) === undefined ? { tokenEndpoint } : undefined
}

// A credential from before the record renews once from the options, which
// become its record. Otherwise an option that's set must match the record, and
// one left unset defers to it.
function recorded(options: Options, current: Credential.OAuth) {
  return Effect.gen(function* () {
    const stored = current.metadata?.[recordKey]
    const issued = stored === undefined ? issuedBy(options) : Option.getOrUndefined(Schema.decodeUnknownOption(IssuedBy)(stored))
    const server = issued && serverIn(issued)
    if (issued === undefined || server === undefined) {
      return yield* Effect.fail(new Error("the credential's record of the server that issued it is invalid; sign in again"))
    }
    if (stored === undefined) return { server, issued, metadata: { ...current.metadata, [recordKey]: issued } }
    for (const name of ["issuer", "tokenEndpoint", "resource"] as const) {
      if (options[name] !== undefined && options[name] !== issued[name]) {
        return yield* Effect.fail(new Error(`${name} has changed since this credential was signed in; sign in again`))
      }
    }
    return { server, issued, metadata: current.metadata }
  })
}

function postTokenRequest(client: Client, tokenEndpoint: string, grant: Record<string, string>) {
  const body = new URLSearchParams({ ...grant, client_id: client.clientID })
  // RFC 8707 section 2.2 lets a server limit a code or refresh token to the
  // resource it was granted for, and some refuse a request that omits it.
  if (client.resource !== undefined) body.set("resource", client.resource)
  const headers = { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" }
  return Effect.suspend(() =>
    fetchJSON(tokenEndpoint, { method: "POST", headers, body }, deadline(tokenRequestTimeoutMs)),
  ).pipe(
    Effect.mapError((failure) => {
      const code = failure.reason === "status" ? failure.error : undefined
      return new Error(`token endpoint ${explain(failure)}${quotable(code) ? `: "${code}"` : ""}`)
    }),
  )
}

// OpenCode sends the token as Bearer, and a client must not use a token type it
// doesn't understand, such as DPoP (RFC 6749 section 7.1).
function acceptTokenResponse(body: unknown) {
  return Effect.gen(function* () {
    const tokens = yield* Schema.decodeUnknownEffect(TokenResponse)(body).pipe(
      Effect.mapError((error) => {
        const field = failedField(error.issue, Object.keys(TokenResponse.fields))
        return new Error(
          field === undefined
            ? "token endpoint returned no JSON token response"
            : `token endpoint's response has no valid ${field}`,
        )
      }),
    )
    if (tokens.token_type.toLowerCase() !== "bearer") {
      const type = quotable(tokens.token_type) ? `of type "${tokens.token_type}"` : "of an unsupported type"
      return yield* Effect.fail(new Error(`token endpoint issued a token ${type}; only Bearer tokens are supported`))
    }
    return tokens
  })
}

// A refresh may omit refresh_token, which keeps the old one (RFC 6749 section 6).
function requestToken(
  client: Client,
  tokenEndpoint: string,
  grant: Record<string, string>,
  metadata: Credential.OAuth["metadata"],
  previousRefresh?: string,
) {
  return Effect.gen(function* () {
    const tokens = yield* postTokenRequest(client, tokenEndpoint, grant).pipe(Effect.flatMap(acceptTokenResponse))
    const refresh = tokens.refresh_token ?? previousRefresh
    if (refresh === undefined) {
      return yield* Effect.fail(
        new Error(
          "token endpoint returned no refresh token: grant the client one, often by adding offline_access to the scope option; " +
            'a provider that ignores offline_access without a consent prompt also needs authorizationParams { "prompt": "consent" }',
        ),
      )
    }
    return Credential.OAuth.make({
      type: "oauth",
      methodID,
      access: tokens.access_token,
      refresh,
      expires: Math.floor(Date.now() + tokens.expires_in * 1000),
      ...(metadata !== undefined ? { metadata } : {}),
    })
  })
}

// OpenCode gives a renewal 30 seconds, but this one can take longer (metadata,
// then the token request), and one OpenCode stops waiting for still runs: the
// server may rotate the refresh token after OpenCode has given up. OpenCode's
// next try carries the same refresh token, so this process keeps renewals keyed
// by it, and a rotated result until its access token expires: the next try takes
// that result rather than spending the old token again, which a server may
// answer by revoking the active refresh token (RFC 9700 section 4.14.2).
const refreshes = new Map<string, Promise<Credential.OAuth>>()

function refreshToken(options: Options, servers: MetadataCache, current: Credential.OAuth) {
  return Effect.tryPromise({
    try: () => {
      const pending = refreshes.get(current.refresh)
      if (pending !== undefined) return pending
      const next = Effect.runPromise(
        Effect.gen(function* () {
          const { server, issued, metadata } = yield* recorded(options, current)
          const tokenEndpoint = "issuer" in server ? (yield* servers(server.issuer)).tokenEndpoint : server.tokenEndpoint
          return yield* requestToken(
            { clientID: options.clientID, resource: issued.resource },
            tokenEndpoint,
            { grant_type: "refresh_token", refresh_token: current.refresh },
            metadata,
            current.refresh,
          )
        }),
      )
      refreshes.set(current.refresh, next)
      const forget = () => refreshes.delete(current.refresh)
      next.then((credential) => {
        if (credential.refresh === current.refresh) return forget()
        // setTimeout fires at once past its 2^31-1 ms ceiling.
        const keep = Math.min(Math.max(0, credential.expires - Date.now()), 2 ** 31 - 1)
        setTimeout(forget, keep).unref()
      }, forget)
      return next
    },
    catch: toError,
  })
}

function authorize(options: Options, authServer: Server): Effect.Effect<IntegrationOAuthAuthorization, Error, Scope.Scope> {
  return Effect.gen(function* () {
    const verifier = randomToken()
    const digest = yield* Effect.promise(() => crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier)))
    const state = randomToken()
    const received = yield* Deferred.make<{ code: string; response: ServerResponse }, Error>()

    const server = createServer((request, response) => {
      const url = URL.parse(request.url ?? "/", "http://127.0.0.1")
      if (request.method !== "GET" || url?.pathname !== callbackPath) {
        reply(response, 404, "Not found")
        return
      }
      // Only the redirect carrying this attempt's state may finish it: anything
      // else on the port (another page, another process) is refused without
      // ending the sign-in or choosing the message it shows.
      if (url.searchParams.get("state") !== state) {
        reply(response, 400, "Sign-in state does not match")
        return
      }
      // From here on the redirect is this attempt's own, so a refusal ends the sign-in.
      const end = (message: string) => {
        reply(response, 400, message)
        Effect.runFork(Deferred.fail(received, new Error(message)))
      }
      const expected = authServer.issuer
      // RFC 6749 section 3.1 forbids repeating a parameter, and a repeat could
      // put a planted value ahead of the real one, such as an `iss` added to the
      // redirect URI where the server matches redirect URIs loosely. The first
      // `state` is the one compared above, so a response whose first `state` is
      // wrong got that 400 and ends nothing; only this attempt's redirect gets here.
      const repeated = ["state", "code", "error", "error_description", ...(expected === undefined ? [] : ["iss"])].find(
        (name) => url.searchParams.getAll(name).length > 1,
      )
      if (repeated !== undefined) return end(`Authorization response repeats ${repeated}`)
      // Mix-up defense (RFC 9207 section 2.4): a response naming another issuer
      // is refused, and so is one without an issuer from a server that sends it.
      const iss = url.searchParams.get("iss")
      if (expected !== undefined && (iss === null ? expected.inResponse : iss !== expected.id)) {
        return end(iss === null ? "Authorization response has no issuer" : "Authorization response came from another issuer")
      }
      const error = url.searchParams.get("error")
      const description = url.searchParams.get("error_description")
      const code = url.searchParams.get("code")
      if (error !== null || description !== null || code === null) {
        // Whatever sent the redirect wrote these words, so they're quoted rather than
        // shown as the plugin's own, and not credited to the server (RFC 9207 section 2.4).
        const named = quotable(error) ? `error "${error}"` : "an error"
        const detail = quotable(description, 256) ? `: "${description}"` : ""
        return end(
          error === null && description === null ? "No authorization code" : `Authorization response carried ${named}${detail}`,
        )
      }
      if (!Effect.runSync(Deferred.succeed(received, { code, response }))) {
        reply(response, 409, "This sign-in has already finished")
      }
    })
    // The attempt's scope closes on success, failure, cancel and expiry. close()
    // frees the port at once and lets a reply in flight reach the browser.
    yield* Effect.addFinalizer(() => Effect.sync(() => server.close()))
    const port = yield* Effect.callback<number, Error>((resume) => {
      const onError = (error: Error) => resume(Effect.fail(error))
      server.once("error", onError)
      server.listen(options.port ?? 0, "127.0.0.1", () => {
        server.off("error", onError)
        const address = server.address()
        resume(
          typeof address === "object" && address !== null
            ? Effect.succeed(address.port)
            : Effect.fail(new Error("loopback listener has no port")),
        )
      })
    })

    const redirect = `http://127.0.0.1:${port}${callbackPath}`
    const url = new URL(authServer.authorizationEndpoint)
    for (const [key, value] of Object.entries({
      ...options.authorizationParams,
      response_type: "code",
      client_id: options.clientID,
      redirect_uri: redirect,
      ...(options.scope !== undefined ? { scope: options.scope } : {}),
      state,
      code_challenge: base64url(new Uint8Array(digest)),
      code_challenge_method: "S256",
    })) {
      url.searchParams.set(key, value)
    }
    if (options.resource !== undefined) url.searchParams.set("resource", options.resource)

    return {
      mode: "auto",
      url: url.toString(),
      instructions: "Finish signing in in your browser.",
      callback: Effect.gen(function* () {
        const { code, response } = yield* Deferred.await(received)
        return yield* requestToken(
          options,
          authServer.tokenEndpoint,
          { grant_type: "authorization_code", code, redirect_uri: redirect, code_verifier: verifier },
          { [recordKey]: issuedBy(options) },
        ).pipe(
          Effect.tap(() => Effect.sync(() => reply(response, 200, "Signed in. You can close this tab."))),
          Effect.tapError((error) => Effect.sync(() => reply(response, 400, error.message))),
          Effect.onInterrupt(() => Effect.sync(() => response.destroy())),
        )
      }),
    }
  })
}

export function registration(options: Options): IntegrationOAuthMethodRegistration {
  const servers = metadataCache()
  return {
    integrationID: options.provider,
    method: { id: methodID, type: "oauth", label: "Sign in" },
    authorize: () => signInServer(options, servers).pipe(Effect.flatMap((authServer) => authorize(options, authServer))),
    refresh: (current) => refreshToken(options, servers, current),
  }
}
