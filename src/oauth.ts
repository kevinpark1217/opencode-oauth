import { Credential, Integration } from "@opencode/plugin/effect"
import type {
  IntegrationOAuthAuthorization,
  IntegrationOAuthMethodRegistration,
} from "@opencode/plugin/effect/integration"
import { Deferred, Effect, Schema, type SchemaIssue, SchemaTransformation, type Scope } from "effect"
import { createServer, type ServerResponse } from "node:http"

const OptionsSchema = Schema.Struct({
  provider: Schema.NonEmptyString,
  clientID: Schema.NonEmptyString,
  authorizationEndpoint: Schema.NonEmptyString,
  tokenEndpoint: Schema.NonEmptyString,
  scope: Schema.NonEmptyString,
  port: Schema.optional(Schema.Int.check(Schema.isBetween({ minimum: 0, maximum: 65535 }))),
  authorizationParams: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  searchURL: Schema.optional(Schema.NonEmptyString),
})
export type Options = typeof OptionsSchema.Type

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
const tokenFields: ReadonlyArray<string> = Object.keys(TokenResponse.fields)

// Returns only the schema's own field names, never text from the response.
function failedField(issue: SchemaIssue.Issue): string | undefined {
  switch (issue._tag) {
    case "Pointer": {
      const [field] = issue.path
      return typeof field === "string" && tokenFields.includes(field) ? field : undefined
    }
    case "Composite":
    case "AnyOf":
      return issue.issues.map(failedField).find((field) => field !== undefined)
    case "Filter":
    case "Encoding":
      return failedField(issue.issue)
    default:
      return undefined
  }
}

const methodID = Integration.MethodID.make("oauth")
const callbackPath = "/callback"
const reservedParams = [
  "response_type",
  "client_id",
  "redirect_uri",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method",
]

export function parseOptions(input: unknown): Options {
  const options = Schema.decodeUnknownSync(OptionsSchema)(input)
  for (const name of ["authorizationEndpoint", "tokenEndpoint", "searchURL"] as const) {
    const value = options[name]
    if (value === undefined) continue
    // Codes and tokens cross these; plain http is accepted only to this machine.
    const url = URL.parse(value)
    const loopback = url?.hostname === "127.0.0.1" || url?.hostname === "[::1]"
    if (url?.protocol !== "https:" && !(url?.protocol === "http:" && loopback)) {
      throw new Error(`${name} must be an https URL`)
    }
  }
  for (const key of Object.keys(options.authorizationParams ?? {})) {
    if (reservedParams.includes(key)) throw new Error(`authorizationParams cannot set ${key}`)
  }
  return options
}

// A hung token endpoint must not hold every model call behind a shared refresh.
const tokenRequestTimeoutMs = 30_000
const asError = (cause: unknown) =>
  cause instanceof Error && cause.name === "TimeoutError"
    ? new Error(`token endpoint did not answer within ${tokenRequestTimeoutMs / 1000} s`)
    : cause instanceof Error
      ? cause
      : new Error(String(cause))

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

// Server text reaches an error message only when it is short and fits OAuth's
// error grammar: printable ASCII without `"` or `\` (RFC 6749 appendix A.7, A.8).
const quotable = (value: unknown, max = 64): value is string =>
  typeof value === "string" && value.length <= max && /^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/.test(value)

function postTokenRequest(client: Pick<Options, "tokenEndpoint" | "clientID">, grant: Record<string, string>) {
  return Effect.tryPromise({
    try: async (signal): Promise<unknown> => {
      const response = await fetch(client.tokenEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", Accept: "application/json" },
        body: new URLSearchParams({ ...grant, client_id: client.clientID }),
        // The body carries a code or a refresh token: never follow it elsewhere.
        redirect: "error",
        signal: AbortSignal.any([signal, AbortSignal.timeout(tokenRequestTimeoutMs)]),
      })
      const json: unknown = await response.json().catch(() => undefined)
      if (!response.ok) {
        const code = (json as { error?: unknown } | undefined)?.error
        throw new Error(`token endpoint answered ${response.status}${quotable(code) ? ` (${code})` : ""}`)
      }
      return json
    },
    catch: asError,
  })
}

// OpenCode sends the token as Bearer, and a client must not use a token type it
// doesn't understand, such as DPoP (RFC 6749 section 7.1).
function acceptTokenResponse(body: unknown) {
  return Effect.gen(function* () {
    const tokens = yield* Schema.decodeUnknownEffect(TokenResponse)(body).pipe(
      Effect.mapError((error) => {
        const field = failedField(error.issue)
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
function requestToken(options: Options, grant: Record<string, string>, previousRefresh?: string) {
  return Effect.gen(function* () {
    const tokens = yield* postTokenRequest(options, grant).pipe(Effect.flatMap(acceptTokenResponse))
    const refresh = tokens.refresh_token ?? previousRefresh
    if (refresh === undefined) {
      return yield* Effect.fail(
        new Error("token endpoint returned no refresh token: grant the client one, often with the offline_access scope"),
      )
    }
    return Credential.OAuth.make({
      type: "oauth",
      methodID,
      access: tokens.access_token,
      refresh,
      expires: Math.floor(Date.now() + tokens.expires_in * 1000),
    })
  })
}

// OpenCode refreshes without a lock (anomalyco/opencode#50759) and servers may
// revoke a rotated refresh token's family on reuse, so concurrent refreshes of
// one token share one request. A rotated result is kept until its access token
// expires, for callers that read the old credential before OpenCode stored the
// new one: the old token is spent, so asking again could only fail.
const refreshes = new Map<string, Promise<Credential.OAuth>>()

function refreshToken(options: Options, current: Credential.OAuth) {
  return Effect.tryPromise({
    try: () => {
      const pending = refreshes.get(current.refresh)
      if (pending !== undefined) return pending
      const next = Effect.runPromise(
        requestToken(options, { grant_type: "refresh_token", refresh_token: current.refresh }, current.refresh),
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
    catch: asError,
  })
}

function authorize(options: Options): Effect.Effect<IntegrationOAuthAuthorization, Error, Scope.Scope> {
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
      const error = url.searchParams.get("error")
      const description = url.searchParams.get("error_description")
      const code = url.searchParams.get("code")
      if (error !== null || description !== null || code === null) {
        const shown = quotable(description, 256) ? description : quotable(error) ? error : undefined
        const message =
          shown ?? (error === null && description === null ? "No authorization code" : "Authorization failed")
        reply(response, 400, message)
        Effect.runFork(Deferred.fail(received, new Error(message)))
        return
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
    const url = new URL(options.authorizationEndpoint)
    for (const [key, value] of Object.entries({
      ...options.authorizationParams,
      response_type: "code",
      client_id: options.clientID,
      redirect_uri: redirect,
      scope: options.scope,
      state,
      code_challenge: base64url(new Uint8Array(digest)),
      code_challenge_method: "S256",
    })) {
      url.searchParams.set(key, value)
    }

    return {
      mode: "auto",
      url: url.toString(),
      instructions: "Finish signing in in your browser.",
      callback: Effect.gen(function* () {
        const { code, response } = yield* Deferred.await(received)
        return yield* requestToken(options, {
          grant_type: "authorization_code",
          code,
          redirect_uri: redirect,
          code_verifier: verifier,
        }).pipe(
          Effect.tap(() => Effect.sync(() => reply(response, 200, "Signed in. You can close this tab."))),
          Effect.tapError((error) => Effect.sync(() => reply(response, 400, error.message))),
          Effect.onInterrupt(() => Effect.sync(() => response.destroy())),
        )
      }),
    }
  })
}

export function registration(options: Options): IntegrationOAuthMethodRegistration {
  return {
    integrationID: options.provider,
    method: { id: methodID, type: "oauth", label: "Sign in" },
    authorize: () => authorize(options),
    refresh: (current) => refreshToken(options, current),
  }
}
