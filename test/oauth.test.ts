import { describe, expect, test } from "bun:test"
import { Credential, Integration } from "@opencode/plugin/effect"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import { type Options, parseOptions, registration } from "../src/oauth.js"

// A token endpoint that records each form it receives and answers with the next
// scripted response.
function tokenEndpoint(responses: Array<Response | { status: number; body: unknown }>) {
  const forms: Array<Record<string, string>> = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request) {
      forms.push(Object.fromEntries(new URLSearchParams(await request.text())))
      const next = responses.shift() ?? { status: 500, body: {} }
      return next instanceof Response ? next : Response.json(next.body, { status: next.status })
    },
  })
  return { url: `http://127.0.0.1:${server.port}/token`, forms, [Symbol.dispose]: () => server.stop(true) }
}

const optionsFor = (tokenURL: string): Options => ({
  provider: "example",
  clientID: "opencode",
  authorizationEndpoint: "https://auth.example/authorize",
  tokenEndpoint: tokenURL,
  scope: "openid offline_access",
})

// Starts a sign-in, lets `browser` answer the authorization URL, and returns
// what the attempt produced; the attempt's scope is closed before it returns.
function signIn(options: Options, browser: (authorization: URL) => Promise<Response>) {
  const method = registration(options)
  return Effect.scoped(
    Effect.gen(function* () {
      const authorization = yield* method.authorize({})
      if (authorization.mode !== "auto") throw new Error("expected an automatic callback")
      const url = new URL(authorization.url)
      const page = browser(url)
      const credential = yield* authorization.callback
      return { url, credential, page: yield* Effect.promise(() => page) }
    }),
  )
}

const redirectOf = (url: URL) => url.searchParams.get("redirect_uri") ?? ""

const credentialWith = (refresh: string) =>
  Credential.OAuth.make({
    type: "oauth",
    methodID: Integration.MethodID.make("oauth"),
    access: "old-access",
    refresh,
    expires: Date.now(),
  })

const bearer = { status: 200, body: { access_token: "access", refresh_token: "refresh", expires_in: 900, token_type: "Bearer" } }

// The browser side of a sign-in: follows the redirect with this attempt's state
// and a code, plus `extra` parameters such as `iss`.
const callback = (extra: Record<string, string> = {}) => (url: URL) =>
  fetch(`${redirectOf(url)}?${new URLSearchParams({ code: "the-code", state: url.searchParams.get("state") ?? "", ...extra })}`)

const failure = (effect: Effect.Effect<unknown, unknown, never>) =>
  Effect.runPromise(Effect.flip(effect)).then((error) => (error instanceof Error ? error.message : String(error)))

// Refreshes one credential repeatedly. Each call sends a new request as long as
// the server does not rotate the refresh token.
function refresher(options: Options) {
  const method = registration(options)
  const current = credentialWith(`refresh-${crypto.randomUUID()}`)
  const run = () => method.refresh?.(current) ?? Effect.die("no refresh")
  return { method, current, credential: () => Effect.runPromise(run()), error: () => failure(run()) }
}

describe("options", () => {
  test("accepts https endpoints, and plain http only to this machine", () => {
    expect(() => parseOptions(optionsFor("https://auth.example/token"))).not.toThrow()
    expect(() => parseOptions(optionsFor("http://127.0.0.1:9/token"))).not.toThrow()
    expect(() => parseOptions(optionsFor("http://auth.example/token"))).toThrow("tokenEndpoint must be an https URL")
    expect(() => parseOptions(optionsFor("not a url"))).toThrow("tokenEndpoint must be an https URL")
    expect(() => parseOptions({ provider: "example" })).toThrow()
    const withSearch = (searchURL: string) => ({ ...optionsFor("https://auth.example/token"), searchURL })
    expect(() => parseOptions(withSearch("https://search.example/search"))).not.toThrow()
    expect(() => parseOptions(withSearch("http://search.example/search"))).toThrow("searchURL must be an https URL")
  })

  test("takes an issuer instead of the endpoints, but not both", () => {
    const base = { provider: "example", clientID: "opencode", scope: "openid" }
    expect(() => parseOptions({ ...base, issuer: "https://auth.example/realms/a" })).not.toThrow()
    expect(() => parseOptions({ ...base, issuer: "http://auth.example" })).toThrow("issuer must be an https URL")
    expect(() => parseOptions({ ...base, issuer: "https://auth.example?tenant=a" })).toThrow(
      "issuer cannot have a query or fragment",
    )
    expect(() => parseOptions({ ...base, issuer: "https://auth.example", tokenEndpoint: "https://auth.example/t" })).toThrow(
      "set issuer, or authorizationEndpoint and tokenEndpoint, not both",
    )
    expect(() => parseOptions({ ...base, tokenEndpoint: "https://auth.example/t" })).toThrow(
      "set issuer, or both authorizationEndpoint and tokenEndpoint",
    )
  })

  test("refuses authorizationParams that would replace the grant's own", () => {
    const withParams = (authorizationParams: Record<string, string>) => ({
      ...optionsFor("https://auth.example/token"),
      authorizationParams,
    })
    expect(() => parseOptions(withParams({ audience: "https://api.example" }))).not.toThrow()
    expect(() => parseOptions(withParams({ redirect_uri: "https://evil.example/" }))).toThrow(
      "authorizationParams cannot set redirect_uri",
    )
    expect(() => parseOptions(withParams({ code_challenge_method: "plain" }))).toThrow()
  })
})

describe("sign-in", () => {
  test("redeems the code with the PKCE verifier and stores the tokens", async () => {
    using tokens = tokenEndpoint([bearer])
    const before = Date.now()
    const { url, credential, page } = await Effect.runPromise(signIn(optionsFor(tokens.url), callback()))

    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      response_type: "code",
      client_id: "opencode",
      scope: "openid offline_access",
      code_challenge_method: "S256",
    })
    expect(redirectOf(url)).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/)
    expect(page.status).toBe(200)

    const form = tokens.forms[0]
    expect(form).toMatchObject({
      grant_type: "authorization_code",
      code: "the-code",
      client_id: "opencode",
      redirect_uri: redirectOf(url),
    })
    expect(form).not.toHaveProperty("resource")
    const challenge = createHash("sha256")
      .update(form?.code_verifier ?? "")
      .digest("base64url")
    expect(challenge).toBe(url.searchParams.get("code_challenge") ?? "")

    expect(credential).toMatchObject({ type: "oauth", methodID: "oauth", access: "access", refresh: "refresh" })
    expect(credential.expires).toBeGreaterThanOrEqual(before + 900_000)
  })

  test("adds authorizationParams to the authorization request", async () => {
    using tokens = tokenEndpoint([bearer])
    const options = { ...optionsFor(tokens.url), authorizationParams: { audience: "https://api.example" } }
    const { url } = await Effect.runPromise(signIn(options, callback()))
    expect(url.searchParams.get("audience")).toBe("https://api.example")
    expect(url.searchParams.get("response_type")).toBe("code")
  })

  test("sends the authorization resource when redeeming the code", async () => {
    using tokens = tokenEndpoint([bearer])
    const resource = "https://api.example/llm"
    const options = {
      ...optionsFor(tokens.url),
      authorizationParams: { resource, audience: "https://api.example", prompt: "login" },
    }
    const { url } = await Effect.runPromise(signIn(options, callback()))
    expect(url.searchParams.get("resource")).toBe(resource)
    expect(tokens.forms[0]).toMatchObject({ grant_type: "authorization_code", resource })
    expect(tokens.forms[0]).not.toHaveProperty("audience")
    expect(tokens.forms[0]).not.toHaveProperty("prompt")
  })

  test("listens on a fixed port when one is set", async () => {
    using tokens = tokenEndpoint([bearer])
    const probe = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response() })
    const port = probe.port
    probe.stop(true)
    const { url } = await Effect.runPromise(signIn({ ...optionsFor(tokens.url), port }, callback()))
    expect(redirectOf(url)).toBe(`http://127.0.0.1:${port}/callback`)
  })

  test("refuses a callback with another state, and still finishes with the real one", async () => {
    using tokens = tokenEndpoint([bearer])
    const statuses: number[] = []
    const { credential } = await Effect.runPromise(
      signIn(optionsFor(tokens.url), async (url) => {
        for (const query of ["code=stolen&state=forged", "error=access_denied&error_description=Phish"]) {
          statuses.push((await fetch(`${redirectOf(url)}?${query}`)).status)
        }
        return callback()(url)
      }),
    )
    expect(statuses).toEqual([400, 400])
    expect(tokens.forms.map((form) => form.code)).toEqual(["the-code"])
    expect(credential.access).toBe("access")
  })

  test("shows a description or error code only when it is short plain text", async () => {
    // Fails a sign-in with a redirect carrying `params`, and returns the message,
    // which the browser tab must show too.
    const failedWith = async (params: Record<string, string>) => {
      let page: Promise<Response> | undefined
      const message = await failure(
        signIn(optionsFor("https://auth.example/token"), (url) => {
          const query = new URLSearchParams({ ...params, state: url.searchParams.get("state") ?? "" })
          page = fetch(`${redirectOf(url)}?${query}`)
          return page
        }),
      )
      expect(await (await page)?.text()).toBe(message)
      return message
    }
    const denied = { error: "access_denied" }
    expect(await failedWith({ ...denied, error_description: "line\n\u001b[31minjected" })).toBe("access_denied")
    expect(await failedWith({ ...denied, error_description: "d".repeat(256) })).toBe("d".repeat(256))
    expect(await failedWith({ ...denied, error_description: "d".repeat(257) })).toBe("access_denied")
    expect(await failedWith({ error: "e".repeat(64) })).toBe("e".repeat(64))
    expect(await failedWith({ error: "e".repeat(65) })).toBe("Authorization failed")
    expect(await failedWith({ error: "bad\ncode" })).toBe("Authorization failed")
    expect(await failedWith({})).toBe("No authorization code")
  })

  test("answers other paths with 404 and a second callback with 409", async () => {
    using tokens = tokenEndpoint([bearer])
    let other = 0
    let second: Promise<Response> | undefined
    const { page } = await Effect.runPromise(
      signIn(optionsFor(tokens.url), async (url) => {
        other = (await fetch(new URL("/elsewhere", redirectOf(url)))).status
        const first = callback()(url)
        second = callback()(url)
        return first
      }),
    )
    expect(other).toBe(404)
    expect([page.status, (await second)?.status].sort()).toEqual([200, 409])
  })

  test("fails when the server issues no refresh token", async () => {
    using tokens = tokenEndpoint([{ status: 200, body: { access_token: "access", expires_in: 900, token_type: "Bearer" } }])
    expect(await failure(signIn(optionsFor(tokens.url), callback()))).toContain("no refresh token")
  })

  test("refuses an access token that is not a Bearer token", async () => {
    using tokens = tokenEndpoint([
      { status: 200, body: { access_token: "access", refresh_token: "r", expires_in: 900, token_type: "DPoP" } },
    ])
    let page: Promise<Response> | undefined
    const error = await failure(
      signIn(optionsFor(tokens.url), (url) => {
        page = callback()(url)
        return page
      }),
    )
    expect(error).toContain('issued a token of type "DPoP"')
    const shown = await page
    expect(shown?.status).toBe(400)
    expect(await shown?.text()).toContain("only Bearer tokens are supported")
  })

  test("closes the loopback listener when the attempt ends", async () => {
    const redirect = await Effect.runPromise(
      Effect.scoped(
        Effect.map(registration(optionsFor("https://auth.example/token")).authorize({}), (authorization) =>
          redirectOf(new URL(authorization.url)),
        ),
      ),
    )
    expect(redirect).not.toBe("")
    expect(fetch(redirect)).rejects.toThrow()
  })
})

describe("refresh", () => {
  test("keeps the refresh token when the server returns none", async () => {
    using tokens = tokenEndpoint([{ status: 200, body: { access_token: "new-access", expires_in: 900, token_type: "Bearer" } }])
    const { current, credential } = refresher(optionsFor(tokens.url))
    const next = await credential()
    expect(tokens.forms).toEqual([{ grant_type: "refresh_token", refresh_token: current.refresh, client_id: "opencode" }])
    expect(next).toMatchObject({ access: "new-access", refresh: current.refresh })
  })

  test("keeps the resource when refreshing without forwarding other authorization parameters", async () => {
    using tokens = tokenEndpoint([bearer])
    const resource = "https://api.example/llm"
    const { current, credential } = refresher({
      ...optionsFor(tokens.url),
      authorizationParams: { resource, audience: "https://api.example", prompt: "login" },
    })
    await credential()
    expect(tokens.forms).toEqual([
      { grant_type: "refresh_token", refresh_token: current.refresh, client_id: "opencode", resource },
    ])
  })

  test("sends one request for concurrent and later refreshes of the same token", async () => {
    using tokens = tokenEndpoint([
      { status: 200, body: { access_token: "new-access", refresh_token: "rotated", expires_in: 900, token_type: "Bearer" } },
    ])
    const { credential } = refresher(optionsFor(tokens.url))
    const [first, second] = await Promise.all([credential(), credential()])
    const late = await credential()
    expect(tokens.forms).toHaveLength(1)
    expect(second).toEqual(first)
    expect(late).toEqual(first)
    expect(first.refresh).toBe("rotated")
  })

  test("asks again when the server did not rotate the refresh token", async () => {
    using tokens = tokenEndpoint([
      { status: 200, body: { access_token: "first", expires_in: 900, token_type: "Bearer" } },
      { status: 200, body: { access_token: "second", expires_in: 900, token_type: "Bearer" } },
    ])
    const { credential } = refresher(optionsFor(tokens.url))
    expect((await credential()).access).toBe("first")
    expect((await credential()).access).toBe("second")
    expect(tokens.forms).toHaveLength(2)
  })

  test("accepts Bearer in any case, and refuses another or a missing token type", async () => {
    using tokens = tokenEndpoint([
      { status: 200, body: { access_token: "lowercase", expires_in: 900, token_type: "bearer" } },
      { status: 200, body: { access_token: "uppercase", expires_in: 900, token_type: "BEARER" } },
      { status: 200, body: { access_token: "bound", expires_in: 900, token_type: "DPoP" } },
      { status: 200, body: { access_token: "padded", expires_in: 900, token_type: "Bearer " } },
      { status: 200, body: { access_token: "untyped", expires_in: 900 } },
      { status: 200, body: { access_token: "empty", expires_in: 900, token_type: "" } },
    ])
    const refresh = refresher(optionsFor(tokens.url))
    expect((await refresh.credential()).access).toBe("lowercase")
    expect((await refresh.credential()).access).toBe("uppercase")
    expect(await refresh.error()).toBe(
      'token endpoint issued a token of type "DPoP"; only Bearer tokens are supported',
    )
    expect(await refresh.error()).toBe(
      'token endpoint issued a token of type "Bearer "; only Bearer tokens are supported',
    )
    expect(await refresh.error()).toBe("token endpoint's response has no valid token_type")
    expect(await refresh.error()).toBe("token endpoint's response has no valid token_type")
    expect(tokens.forms).toHaveLength(6)
  })

  test("accepts expires_in as a number or a string of digits, and names a bad one", async () => {
    const refused = [0, "0", "soon", " 900", "0x10", "1e3", "+900", "9.5", undefined]
    using tokens = tokenEndpoint([
      { status: 200, body: { access_token: "string", expires_in: "900", token_type: "Bearer" } },
      ...refused.map((expires_in) => ({ status: 200, body: { access_token: "a", expires_in, token_type: "Bearer" } })),
    ])
    const refresh = refresher(optionsFor(tokens.url))
    const before = Date.now()
    const credential = await refresh.credential()
    expect(credential.access).toBe("string")
    expect(credential.expires).toBeGreaterThanOrEqual(before + 900_000)
    for (const value of refused) {
      expect([value, await refresh.error()]).toEqual([value, "token endpoint's response has no valid expires_in"])
    }
  })

  test("treats a null refresh_token as none", async () => {
    using tokens = tokenEndpoint([
      { status: 200, body: { access_token: "new-access", expires_in: 900, token_type: "Bearer", refresh_token: null } },
    ])
    const refresh = refresher(optionsFor(tokens.url))
    expect(await refresh.credential()).toMatchObject({ access: "new-access", refresh: refresh.current.refresh })
  })

  test("quotes an error code or token type only when it is short plain text", async () => {
    using tokens = tokenEndpoint([
      { status: 400, body: { error: 'invalid_grant"\ninjected' } },
      { status: 200, body: { access_token: "a", expires_in: 900, token_type: "x\ninjected" } },
      { status: 200, body: { access_token: "a", expires_in: 900, token_type: "x".repeat(64) } },
      { status: 200, body: { access_token: "a", expires_in: 900, token_type: "x".repeat(65) } },
    ])
    const refresh = refresher(optionsFor(tokens.url))
    const unsupported = "token endpoint issued a token of an unsupported type; only Bearer tokens are supported"
    expect(await refresh.error()).toBe("token endpoint answered 400")
    expect(await refresh.error()).toBe(unsupported)
    expect(await refresh.error()).toContain(`of type "${"x".repeat(64)}"`)
    expect(await refresh.error()).toBe(unsupported)
  })

  test("does not follow a redirect with the refresh token", async () => {
    using elsewhere = tokenEndpoint([])
    using tokens = tokenEndpoint([new Response(null, { status: 307, headers: { Location: elsewhere.url } })])
    await refresher(optionsFor(tokens.url)).error()
    expect(tokens.forms).toHaveLength(1)
    expect(elsewhere.forms).toHaveLength(0)
  })

  test("rejects a success that carries no token, and names a missing access_token", async () => {
    using tokens = tokenEndpoint([
      new Response("<html>login</html>", { status: 200 }),
      { status: 200, body: { expires_in: 900, token_type: "Bearer" } },
    ])
    const refresh = refresher(optionsFor(tokens.url))
    expect(await refresh.error()).toBe("token endpoint returned no JSON token response")
    expect(await refresh.error()).toBe("token endpoint's response has no valid access_token")
  })

  test("fails with the OAuth error code, and retries on the next attempt", async () => {
    using tokens = tokenEndpoint([
      { status: 400, body: { error: "invalid_grant", error_description: "do not echo" } },
      { status: 200, body: { access_token: "new-access", expires_in: 900, token_type: "Bearer" } },
    ])
    const refresh = refresher(optionsFor(tokens.url))
    const error = await refresh.error()
    expect(error).toContain("400 (invalid_grant)")
    expect(error).not.toContain("do not echo")
    const next = await refresh.credential()
    expect(next.access).toBe("new-access")
    expect(tokens.forms).toHaveLength(2)
  })
})

// An authorization server on this machine that publishes its metadata at one
// well-known location and answers token requests with the scripted responses.
function authServer(
  input: {
    at?: "openid-configuration" | "oauth-authorization-server"
    path?: string
    metadata?: (issuer: string) => Record<string, unknown>
    failFirst?: number
    tokens?: Array<{ status: number; body: unknown }>
  } = {},
) {
  const paths: string[] = []
  const forms: Array<Record<string, string>> = []
  const tokens = [...(input.tokens ?? [])]
  let failures = input.failFirst ?? 0
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    async fetch(request): Promise<Response> {
      const path = new URL(request.url).pathname
      paths.push(path)
      if (path === "/token") {
        forms.push(Object.fromEntries(new URLSearchParams(await request.text())))
        const next = tokens.shift() ?? { status: 500, body: {} }
        return Response.json(next.body, { status: next.status })
      }
      const base = (input.path ?? "").replace(/\/$/, "")
      const published =
        input.at === "oauth-authorization-server"
          ? `/.well-known/oauth-authorization-server${base}`
          : `${base}/.well-known/openid-configuration`
      if (path !== published) return new Response(null, { status: 404 })
      if (failures-- > 0) return new Response(null, { status: 503 })
      return Response.json({
        issuer,
        authorization_endpoint: `${origin}/authorize`,
        token_endpoint: `${origin}/token`,
        code_challenge_methods_supported: ["S256"],
        ...input.metadata?.(issuer),
      })
    },
  })
  const origin = `http://127.0.0.1:${server.port}`
  const issuer: string = `${origin}${input.path ?? ""}`
  const options: Options = { provider: "example", clientID: "opencode", issuer, scope: "openid offline_access" }
  return { origin, issuer, options, paths, forms, [Symbol.dispose]: () => server.stop(true) }
}

describe("discovery", () => {
  test("signs in with the endpoints from the issuer's OpenID Connect metadata", async () => {
    using auth = authServer({ path: "/application/o/app/", tokens: [bearer] })
    const { url, credential } = await Effect.runPromise(signIn(auth.options, callback()))
    expect(`${url.origin}${url.pathname}`).toBe(`${auth.origin}/authorize`)
    expect(auth.forms[0]).toMatchObject({ grant_type: "authorization_code", code: "the-code" })
    expect(credential.access).toBe("access")
    expect(auth.paths).toEqual(["/application/o/app/.well-known/openid-configuration", "/token"])
  })

  test("falls back to the RFC 8414 location, inserted before the issuer's path", async () => {
    using auth = authServer({ at: "oauth-authorization-server", path: "/realms/a", tokens: [bearer] })
    await Effect.runPromise(signIn(auth.options, callback()))
    expect(auth.paths).toEqual([
      "/realms/a/.well-known/openid-configuration",
      "/.well-known/oauth-authorization-server/realms/a",
      "/token",
    ])
  })

  test("refuses metadata for another issuer, with insecure endpoints, or without S256", async () => {
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ issuer: "https://evil.example" }, 'authorization server metadata names "https://evil.example", not'],
      [{ token_endpoint: "http://evil.example/token" }, "authorization server metadata's token_endpoint must be an https URL"],
      [{ code_challenge_methods_supported: ["plain"] }, "authorization server does not support PKCE with S256"],
      [{ authorization_endpoint: 42 }, "authorization server metadata has no valid authorization_endpoint"],
    ]
    for (const [metadata, message] of cases) {
      using auth = authServer({ metadata: () => metadata })
      expect(await failure(Effect.scoped(registration(auth.options).authorize({})))).toContain(message)
      expect(auth.paths).not.toContain("/token")
    }
  })

  test("checks the issuer in the authorization response (RFC 9207)", async () => {
    using strict = authServer({ metadata: () => ({ authorization_response_iss_parameter_supported: true }), tokens: [bearer] })
    expect(await failure(signIn(strict.options, callback()))).toBe("Authorization response has no issuer")
    const denied = (url: URL) =>
      fetch(`${redirectOf(url)}?${new URLSearchParams({ error: "access_denied", state: url.searchParams.get("state") ?? "" })}`)
    expect(await failure(signIn(strict.options, denied))).toBe("Authorization response has no issuer")
    expect(await failure(signIn(strict.options, callback({ iss: "https://evil.example" })))).toBe(
      "Authorization response came from another issuer",
    )
    expect((await Effect.runPromise(signIn(strict.options, callback({ iss: strict.issuer })))).credential.access).toBe("access")

    using lenient = authServer({ tokens: [bearer] })
    expect(await failure(signIn(lenient.options, callback({ iss: "https://evil.example" })))).toBe(
      "Authorization response came from another issuer",
    )
    expect((await Effect.runPromise(signIn(lenient.options, callback()))).credential.access).toBe("access")
  })

  test("shares and keeps valid metadata for sign-ins and refreshes, and retries after a failure", async () => {
    using auth = authServer({ failFirst: 1, tokens: [bearer] })
    const { method, credential } = refresher(auth.options)
    expect(await failure(Effect.scoped(method.authorize({})))).toContain("answered 503")
    const authorizeURL = () => Effect.runPromise(Effect.scoped(Effect.map(method.authorize({}), (a) => new URL(a.url))))
    const [url] = await Promise.all([authorizeURL(), authorizeURL()])
    expect(`${url.origin}${url.pathname}`).toBe(`${auth.origin}/authorize`)
    const renewed = await credential()
    expect(renewed.access).toBe("access")
    expect(auth.paths.filter((path) => path.startsWith("/.well-known/"))).toEqual([
      "/.well-known/openid-configuration",
      "/.well-known/openid-configuration",
    ])
  })
})
