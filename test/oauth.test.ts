import { describe, expect, spyOn, test } from "bun:test"
import { Credential, Integration } from "@opencode/plugin/effect"
import { Effect } from "effect"
import { createHash } from "node:crypto"
import type { PluginContext } from "../src/discovery.js"
import { registration } from "../src/oauth.js"
import { type Options, parseOptions } from "../src/options.js"

// OpenCode's side of the plugin: plugin storage in memory, failing where asked,
// and the provider's settings, which discovery reads its baseURL from.
function hostWith(input: { settings?: Record<string, unknown>; storage?: Map<string, unknown>; failing?: "get" | "set" } = {}) {
  const storage = input.storage ?? new Map<string, unknown>()
  const broken = (operation: "get" | "set") => input.failing === operation
  const host = {
    provider: {
      get: () =>
        input.settings === undefined
          ? Effect.fail(new Error("Provider not found"))
          : Effect.succeed({ data: { id: "example", settings: input.settings } }),
    },
    storage: {
      get: (key: string) => (broken("get") ? Effect.die(new Error("storage down")) : Effect.sync(() => storage.get(key))),
      set: (key: string, value: unknown) =>
        broken("set") ? Effect.die(new Error("storage down")) : Effect.sync(() => void storage.set(key, value)),
      remove: (key: string) =>
        broken("set") ? Effect.die(new Error("storage down")) : Effect.sync(() => void storage.delete(key)),
    },
  }
  return Object.assign(host as unknown as PluginContext, { stored: storage })
}

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
function signIn(options: Options, browser: (authorization: URL) => Promise<Response>, host: PluginContext = hostWith()) {
  const method = registration(host, options)
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

const credentialWith = (refresh: string, metadata?: Record<string, unknown>) =>
  Credential.OAuth.make({
    type: "oauth",
    methodID: Integration.MethodID.make("oauth"),
    access: "old-access",
    refresh,
    expires: Date.now(),
    ...(metadata !== undefined ? { metadata } : {}),
  })

const bearer = { status: 200, body: { access_token: "access", refresh_token: "refresh", expires_in: 900, token_type: "Bearer" } }

// The browser side of a sign-in: follows the redirect with this attempt's state
// and a code, plus `extra` parameters such as `iss`.
const callback = (extra: Record<string, string> = {}) => (url: URL) =>
  fetch(`${redirectOf(url)}?${new URLSearchParams({ code: "the-code", state: url.searchParams.get("state") ?? "", ...extra })}`)

// The browser side of a sign-in whose redirect repeats `name`: the callback's
// parameters, with `values` appended.
const repeating =
  (name: string, values = ["planted", "planted"]) =>
  (url: URL) => {
    const query = new URLSearchParams({ code: "the-code", state: url.searchParams.get("state") ?? "" })
    for (const value of values) query.append(name, value)
    return fetch(`${redirectOf(url)}?${query}`)
  }

const failure = (effect: Effect.Effect<unknown, unknown, never>) =>
  Effect.runPromise(Effect.flip(effect)).then((error) => (error instanceof Error ? error.message : String(error)))

// Refreshes one credential repeatedly. Each call sends a new request as long as
// the server does not rotate the refresh token.
function refresher(options: Options) {
  const method = registration(hostWith(), options)
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

  test("refuses a URL with a user name or password, or without a host", () => {
    for (const url of [
      "https://idp@evil.example/token",
      "https://user:pw@auth.example/token",
      "https://@auth.example/token",
      "https://:@auth.example/token",
      "https://auth.example\t@evil.example/token",
      "https:///v1",
      "https:////v1",
      "https://\t/v1",
      "https:/v1",
    ]) {
      expect(() => parseOptions(optionsFor(url))).toThrow("tokenEndpoint must be an https URL")
    }
  })

  test("refuses an endpoint with a fragment", () => {
    expect(() => parseOptions(optionsFor("https://auth.example/token#"))).toThrow("tokenEndpoint cannot have a fragment")
    expect(() => parseOptions(optionsFor("https://auth.example/token#a"))).toThrow("tokenEndpoint cannot have a fragment")
  })

  test("refuses an empty scope rather than treating it as unset", () => {
    expect(() => parseOptions({ ...optionsFor("https://auth.example/token"), scope: "" })).toThrow('at ["scope"]')
  })

  test("refuses an option it doesn't know, naming it", () => {
    expect(() => parseOptions({ ...optionsFor("https://auth.example/token"), isuer: "https://auth.example" })).toThrow(
      'Expected no excess property\n  at ["isuer"]',
    )
  })

  test("takes an issuer or the endpoints, not both, or neither for discovery", () => {
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
      "set both authorizationEndpoint and tokenEndpoint, or leave out both and issuer",
    )
    expect(() => parseOptions(base)).not.toThrow()
    expect(() => parseOptions({ ...base, issuer: "" })).toThrow('at ["issuer"]')
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
    expect(() => parseOptions(withParams({ resource: "https://api.example" }))).toThrow(
      "set resource as an option of its own, not in authorizationParams",
    )
  })

  test("takes resource as an absolute URI without a fragment", () => {
    const withResource = (resource: string) => ({ ...optionsFor("https://auth.example/token"), resource })
    const invalid = "resource must be an absolute URI without a fragment"
    expect(() => parseOptions(withResource("https://api.example/llm"))).not.toThrow()
    expect(() => parseOptions(withResource("urn:example:llm"))).not.toThrow()
    expect(() => parseOptions(withResource("api.example/llm"))).toThrow(invalid)
    expect(() => parseOptions(withResource("https://api.example/llm "))).toThrow(invalid)
    expect(() => parseOptions(withResource("https://api.example/#llm"))).toThrow(invalid)
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
    const challenge = createHash("sha256")
      .update(form?.code_verifier ?? "")
      .digest("base64url")
    expect(challenge).toBe(url.searchParams.get("code_challenge") ?? "")

    expect(credential).toMatchObject({ type: "oauth", methodID: "oauth", access: "access", refresh: "refresh" })
    expect(credential.expires).toBeGreaterThanOrEqual(before + 900_000)
  })

  test("sends no scope of its own when scope is unset, and keeps one in the endpoint's query", async () => {
    using tokens = tokenEndpoint([bearer, bearer])
    const { scope: _, ...unscoped } = optionsFor(tokens.url)
    const plain = await Effect.runPromise(signIn(parseOptions(unscoped), callback()))
    expect(plain.url.searchParams.has("scope")).toBe(false)
    const authorizationEndpoint = "https://auth.example/authorize?scope=openid"
    const kept = await Effect.runPromise(signIn({ ...unscoped, authorizationEndpoint }, callback()))
    expect(kept.url.searchParams.getAll("scope")).toEqual(["openid"])
  })

  test("adds authorizationParams to the authorization request", async () => {
    using tokens = tokenEndpoint([bearer])
    const options = { ...optionsFor(tokens.url), authorizationParams: { audience: "https://api.example" } }
    const { url } = await Effect.runPromise(signIn(options, callback()))
    expect(url.searchParams.get("audience")).toBe("https://api.example")
    expect(url.searchParams.get("response_type")).toBe("code")
  })

  test("sends the resource with the authorization request and the code", async () => {
    using tokens = tokenEndpoint([bearer])
    const resource = "https://api.example/llm"
    const { url } = await Effect.runPromise(signIn({ ...optionsFor(tokens.url), resource }, callback()))
    expect(url.searchParams.get("resource")).toBe(resource)
    expect(tokens.forms[0]).toMatchObject({ grant_type: "authorization_code", resource })
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
        const real = url.searchParams.get("state") ?? ""
        for (const query of [
          "code=stolen&state=forged",
          "error=access_denied&error_description=Phish",
          `code=stolen&state=forged&state=${real}`,
        ]) {
          statuses.push((await fetch(`${redirectOf(url)}?${query}`)).status)
        }
        return callback()(url)
      }),
    )
    expect(statuses).toEqual([400, 400, 400])
    expect(tokens.forms.map((form) => form.code)).toEqual(["the-code"])
    expect(credential.access).toBe("access")
  })

  test("refuses a callback that repeats a parameter it reads, and ignores other repeats", async () => {
    using tokens = tokenEndpoint([bearer, bearer])
    const options = optionsFor(tokens.url)
    for (const name of ["state", "code", "error", "error_description"]) {
      expect(await failure(signIn(options, repeating(name)))).toBe(`Authorization response repeats ${name}`)
    }
    expect(tokens.forms).toEqual([])
    // Without an issuer the callback doesn't read `iss`.
    for (const name of ["iss", "unrelated"]) {
      expect((await Effect.runPromise(signIn(options, repeating(name)))).credential.access).toBe("access")
    }
  })

  test("quotes a description or error code only when it is short plain text, never as the whole message", async () => {
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
    const carried = (said: string) => `Authorization response carried ${said}`
    expect(await failedWith({ ...denied, error_description: "line\n\u001b[31minjected" })).toBe(carried('error "access_denied"'))
    expect(await failedWith({ ...denied, error_description: "d".repeat(256) })).toBe(
      carried(`error "access_denied": "${"d".repeat(256)}"`),
    )
    expect(await failedWith({ ...denied, error_description: "d".repeat(257) })).toBe(carried('error "access_denied"'))
    expect(await failedWith({ error_description: "Set issuer to https://evil.example" })).toBe(
      carried('an error: "Set issuer to https://evil.example"'),
    )
    expect(await failedWith({ error: "e".repeat(64) })).toBe(carried(`error "${"e".repeat(64)}"`))
    expect(await failedWith({ error: "e".repeat(65) })).toBe(carried("an error"))
    expect(await failedWith({ error: "bad\ncode" })).toBe(carried("an error"))
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
        Effect.map(registration(hostWith(), optionsFor("https://auth.example/token")).authorize({}), (authorization) =>
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

  test("sends the resource with the refresh token", async () => {
    using tokens = tokenEndpoint([bearer])
    const resource = "https://api.example/llm"
    const { current, credential } = refresher({ ...optionsFor(tokens.url), resource })
    await credential()
    expect(tokens.forms).toEqual([
      { grant_type: "refresh_token", refresh_token: current.refresh, client_id: "opencode", resource },
    ])
  })

  test("keeps a renewal OpenCode stopped waiting for, so its next try doesn't spend the token again", async () => {
    let requests = 0
    const server = Bun.serve({
      hostname: "127.0.0.1",
      port: 0,
      async fetch() {
        requests++
        await Bun.sleep(200)
        return Response.json({ access_token: "new-access", refresh_token: "rotated", expires_in: 900, token_type: "Bearer" })
      },
    })
    try {
      const { method, current, credential } = refresher(optionsFor(`http://127.0.0.1:${server.port}/token`))
      // OpenCode gives a renewal 30 seconds; this one, 50 ms.
      const abandoned = method.refresh?.(current) ?? Effect.die("no refresh")
      expect((await Effect.runPromiseExit(abandoned.pipe(Effect.timeout("50 millis"))))._tag).toBe("Failure")
      expect((await credential()).refresh).toBe("rotated")
      expect((await credential()).refresh).toBe("rotated")
      expect(requests).toBe(1)
    } finally {
      server.stop(true)
    }
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
    expect(await refresher(optionsFor(tokens.url)).error()).toBe(
      "token endpoint answered with a redirect, which the plugin does not follow",
    )
    expect(tokens.forms).toHaveLength(1)
    expect(elsewhere.forms).toHaveLength(0)
  })

  test("reports a timeout, an untrusted certificate or an unreachable host without the runtime's message", async () => {
    const untrusted =
      "token endpoint has a certificate that isn't trusted; for a private CA, set NODE_EXTRA_CA_CERTS to its certificate file"
    const coded = (error: Error, code: string) => Object.assign(error, { code })
    const cases: Array<[Error, string]> = [
      [new DOMException("The operation timed out.", "TimeoutError"), "token endpoint did not answer within 30 s"],
      [coded(new TypeError("self signed certificate"), "DEPTH_ZERO_SELF_SIGNED_CERT"), untrusted],
      [new TypeError("fetch failed", { cause: coded(new Error("self-signed certificate"), "SELF_SIGNED_CERT_IN_CHAIN") }), untrusted],
      [
        coded(new TypeError("certificate has expired"), "CERT_HAS_EXPIRED"),
        "token endpoint has an invalid certificate, such as an expired one or one for another name",
      ],
      [coded(new TypeError("getaddrinfo ENOTFOUND auth.example"), "ENOTFOUND"), "token endpoint could not be reached"],
    ]
    for (const [error, message] of cases) {
      const fetched = spyOn(globalThis, "fetch").mockRejectedValue(error)
      try {
        expect(await refresher(optionsFor("https://auth.example/token")).error()).toBe(message)
      } finally {
        fetched.mockRestore()
      }
    }
  })

  test("reports an error's status even when its body breaks off", async () => {
    const server = Bun.listen({
      hostname: "127.0.0.1",
      port: 0,
      socket: {
        data(socket) {
          socket.end('HTTP/1.1 400 Bad Request\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{"error":')
        },
      },
    })
    try {
      expect(await refresher(optionsFor(`http://127.0.0.1:${server.port}/token`)).error()).toBe("token endpoint answered 400")
    } finally {
      server.stop(true)
    }
  })

  test("refuses a response over 4 MiB, counted on its decoded size, and one it can't decode", async () => {
    const gzip = { "Content-Type": "application/json", "Content-Encoding": "gzip" }
    const body = { access_token: "a".repeat(4 * 1024 * 1024), expires_in: 900, token_type: "Bearer" }
    const huge = Bun.gzipSync(JSON.stringify(body))
    expect(huge.byteLength).toBeLessThan(64 * 1024)
    // Not valid gzip: had the runtime inflated it, the error would be its own.
    using tokens = tokenEndpoint([new Response(huge, { headers: gzip }), new Response("not gzip", { headers: gzip })])
    const refresh = refresher(optionsFor(tokens.url))
    expect(await refresh.error()).toBe("token endpoint answered with more than 4 MiB")
    expect(await refresh.error()).toBe("token endpoint answered with a body the plugin can't decode")
  })

  test("rejects a success that carries no token, and names a missing access_token", async () => {
    using tokens = tokenEndpoint([
      new Response("<html>login</html>", { status: 200 }),
      { status: 200, body: [] },
      { status: 200, body: { expires_in: 900, token_type: "Bearer" } },
    ])
    const refresh = refresher(optionsFor(tokens.url))
    expect(await refresh.error()).toBe("token endpoint did not answer with JSON")
    expect(await refresh.error()).toBe("token endpoint returned no JSON token response")
    expect(await refresh.error()).toBe("token endpoint's response has no valid access_token")
  })

  test("fails with the OAuth error code, and retries on the next attempt", async () => {
    using tokens = tokenEndpoint([
      { status: 400, body: { error: "invalid_grant", error_description: "do not echo" } },
      { status: 200, body: { access_token: "new-access", expires_in: 900, token_type: "Bearer" } },
    ])
    const refresh = refresher(optionsFor(tokens.url))
    expect(await refresh.error()).toBe('token endpoint answered 400: "invalid_grant"')
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

describe("the record of the server that issued a credential", () => {
  const renew = (options: Options, current: Credential.OAuth) =>
    registration(hostWith(), options).refresh?.(current) ?? Effect.die("no refresh")
  const withRecord = (record: unknown, other: Record<string, unknown> = {}) =>
    credentialWith(`refresh-${crypto.randomUUID()}`, { ...other, "opencode-oauth": record })

  test("is written at sign-in: the issuer or the token endpoint, and the resource", async () => {
    using tokens = tokenEndpoint([bearer])
    const resource = "https://api.example/llm"
    const configured = await Effect.runPromise(signIn({ ...optionsFor(tokens.url), resource }, callback()))
    expect(configured.credential.metadata).toEqual({ "opencode-oauth": { tokenEndpoint: tokens.url, resource } })
    using auth = authServer({ tokens: [bearer] })
    const byIssuer = await Effect.runPromise(signIn(auth.options, callback()))
    expect(byIssuer.credential.metadata).toEqual({ "opencode-oauth": { issuer: auth.issuer } })
  })

  test("is kept as stored across renewals, with other metadata and fields it doesn't know", async () => {
    using tokens = tokenEndpoint([bearer, bearer])
    const current = withRecord({ tokenEndpoint: tokens.url, added: "later" }, { other: 1 })
    const first = await Effect.runPromise(renew(optionsFor(tokens.url), current))
    const second = await Effect.runPromise(renew(optionsFor(tokens.url), first))
    expect(second.metadata).toEqual(current.metadata)
    expect(tokens.forms).toHaveLength(2)
  })

  test("is written at the first renewal of a credential from before it", async () => {
    using tokens = tokenEndpoint([bearer])
    const next = await Effect.runPromise(renew(optionsFor(tokens.url), credentialWith(`refresh-${crypto.randomUUID()}`)))
    expect(next.metadata).toEqual({ "opencode-oauth": { tokenEndpoint: tokens.url } })
  })

  test("refuses a renewal when a set option differs from the record, naming the option", async () => {
    using tokens = tokenEndpoint([])
    const resource = "https://api.example/llm"
    const byIssuer = { provider: "example", clientID: "opencode", issuer: "https://b.example", scope: "openid" }
    const cases: Array<[unknown, Options, string]> = [
      [{ issuer: "https://a.example" }, byIssuer, "issuer"],
      [{ tokenEndpoint: tokens.url }, byIssuer, "issuer"],
      [{ issuer: "https://b.example" }, optionsFor(tokens.url), "tokenEndpoint"],
      [{ tokenEndpoint: "https://auth.example/token" }, optionsFor(tokens.url), "tokenEndpoint"],
      [{ tokenEndpoint: tokens.url, resource }, { ...optionsFor(tokens.url), resource: "https://api.example/other" }, "resource"],
      [{ tokenEndpoint: tokens.url }, { ...optionsFor(tokens.url), resource }, "resource"],
    ]
    for (const [record, options, name] of cases) {
      expect(await failure(renew(options, withRecord(record)))).toBe(
        `${name} has changed since this credential was signed in; sign in again`,
      )
    }
    expect(tokens.forms).toHaveLength(0)
  })

  test("refuses a renewal from a record that doesn't decode or fails the checks of a configured server", async () => {
    using tokens = tokenEndpoint([])
    for (const record of [
      "https://auth.example",
      { tokenEndpoint: 42 },
      {},
      { issuer: "https://auth.example", tokenEndpoint: tokens.url },
      { issuer: "http://evil.example" },
      { issuer: "https://auth.example?tenant=a" },
      { tokenEndpoint: "https://idp@evil.example/token" },
      { tokenEndpoint: `${tokens.url}#` },
      { tokenEndpoint: tokens.url, resource: "api.example/llm" },
    ]) {
      expect(await failure(renew(optionsFor(tokens.url), withRecord(record)))).toBe(
        "the credential's record of the server that issued it is invalid; sign in again",
      )
    }
    expect(tokens.forms).toHaveLength(0)
  })

  test("keeps sending a recorded resource after the option is removed", async () => {
    using tokens = tokenEndpoint([bearer])
    const resource = "https://api.example/llm"
    const current = withRecord({ tokenEndpoint: tokens.url, resource })
    await Effect.runPromise(renew(optionsFor(tokens.url), current))
    expect(tokens.forms).toEqual([{ grant_type: "refresh_token", refresh_token: current.refresh, client_id: "opencode", resource }])
  })
})

describe("issuer metadata", () => {
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
      [{ issuer: "https://evil.example\nSet issuer to it" }, "authorization server metadata names a different issuer, not"],
      [{ token_endpoint: "http://evil.example/token" }, "authorization server metadata's token_endpoint must be an https URL"],
      [{ token_endpoint: "https://auth.example/token#" }, "authorization server metadata's token_endpoint cannot have a fragment"],
      [{ code_challenge_methods_supported: ["plain"] }, "authorization server does not support PKCE with S256"],
      [{ authorization_endpoint: 42 }, "authorization server metadata has no valid authorization_endpoint"],
    ]
    for (const [metadata, message] of cases) {
      using auth = authServer({ metadata: () => metadata })
      expect(await failure(Effect.scoped(registration(hostWith(), auth.options).authorize({})))).toContain(message)
      expect(auth.paths).not.toContain("/token")
    }
  })

  test("does not follow a redirect for metadata", async () => {
    using elsewhere = authServer()
    const server = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => Response.redirect(elsewhere.issuer, 302) })
    try {
      const issuer = `http://127.0.0.1:${server.port}`
      const options = { provider: "example", clientID: "opencode", issuer, scope: "openid" }
      expect(await failure(Effect.scoped(registration(hostWith(), options).authorize({})))).toBe(
        `authorization server metadata at ${issuer}/.well-known/openid-configuration answered with a redirect, which the plugin does not follow`,
      )
      expect(elsewhere.paths).toEqual([])
    } finally {
      server.stop(true)
    }
  })

  test("refuses an http endpoint named by metadata fetched over https", async () => {
    const metadata = {
      issuer: "https://auth.example",
      authorization_endpoint: "https://auth.example/authorize",
      token_endpoint: "http://127.0.0.1:9/token",
    }
    const fetched = spyOn(globalThis, "fetch").mockResolvedValue(Response.json(metadata))
    try {
      const options = { provider: "example", clientID: "opencode", issuer: metadata.issuer, scope: "openid" }
      expect(await failure(Effect.scoped(registration(hostWith(), options).authorize({})))).toContain(
        "authorization server metadata's token_endpoint must be an https URL",
      )
    } finally {
      fetched.mockRestore()
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
    expect(await failure(signIn(strict.options, repeating("iss", [strict.issuer, "https://evil.example"])))).toBe(
      "Authorization response repeats iss",
    )
    expect((await Effect.runPromise(signIn(strict.options, callback({ iss: strict.issuer })))).credential.access).toBe("access")

    using lenient = authServer({ tokens: [bearer] })
    expect(await failure(signIn(lenient.options, repeating("iss", [lenient.issuer, "https://evil.example"])))).toBe(
      "Authorization response repeats iss",
    )
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

// An API that publishes its protected resource metadata (RFC 9728) at the
// well-known path for a baseURL ending in `path`.
function api(document: (identifier: string) => unknown, path = "/v1") {
  const paths: string[] = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request): Response {
      const requested = new URL(request.url).pathname
      paths.push(requested)
      if (requested !== `/.well-known/oauth-protected-resource${path}`) return new Response(null, { status: 404 })
      return Response.json(document(identifier))
    },
  })
  const identifier: string = `http://127.0.0.1:${server.port}${path}`
  return { identifier, paths, [Symbol.dispose]: () => server.stop(true) }
}

describe("finding the server from the API", () => {
  const options: Options = { provider: "example", clientID: "opencode" }
  const advice = "; set issuer to your identity provider's issuer, as its administrator gives it"
  // An identity provider that discovery accepts: RFC 9207, S256 and offline_access.
  const identityProvider = (tokens: Array<{ status: number; body: unknown }> = [bearer]) =>
    authServer({
      metadata: () => ({ authorization_response_iss_parameter_supported: true, scopes_supported: ["openid", "offline_access"] }),
      tokens,
    })
  const naming = (issuer: string, extra: Record<string, unknown> = {}) => (identifier: string) => ({
    resource: identifier,
    authorization_servers: [issuer],
    scopes_supported: ["models:read"],
    ...extra,
  })
  const signInWith = (host: PluginContext, issuer: string) => signIn(options, callback({ iss: issuer }), host)
  const failing = (host: PluginContext) => failure(Effect.scoped(registration(host, options).authorize({})))
  const renew = (method: ReturnType<typeof registration>, current: Credential.OAuth) =>
    method.refresh?.(current) ?? Effect.die("no refresh")

  test("finds the server from the API, for a baseURL with or without a path, and records and binds it", async () => {
    for (const path of ["/v1", ""]) {
      using auth = identityProvider()
      // A server listed twice is still one server.
      using llm = api((identifier) => ({ ...naming(auth.issuer)(identifier), authorization_servers: [auth.issuer, auth.issuer] }), path)
      const host = hostWith({ settings: { baseURL: `${llm.identifier}/` } })
      const { url, credential } = await Effect.runPromise(signInWith(host, auth.issuer))
      expect(llm.paths).toEqual([`/.well-known/oauth-protected-resource${path}`])
      expect(url.searchParams.get("resource")).toBe(llm.identifier)
      expect(url.searchParams.get("scope")).toBe("models:read offline_access")
      expect(auth.forms[0]?.resource).toBe(llm.identifier)
      expect(credential.metadata).toEqual({ "opencode-oauth": { issuer: auth.issuer, resource: llm.identifier } })
      expect(host.stored.get("binding/example")).toBe(auth.issuer)
    }
  })

  test("stops with the advice to set issuer, and never prints the server the API names", async () => {
    using auth = authServer({ metadata: () => ({ authorization_response_iss_parameter_supported: true }) })
    using unsigned = authServer()
    const flagged = { authorization_response_iss_parameter_supported: true }
    using impostor = authServer({ metadata: () => ({ ...flagged, issuer: "https://evil.example" }) })
    using incomplete = authServer({ metadata: () => ({ ...flagged, token_endpoint: 42 }) })
    using fragmented = authServer({ metadata: (issuer) => ({ ...flagged, token_endpoint: `${issuer}/token#` }) })
    expect(await failing(hostWith({ settings: {} }))).toBe(
      `the provider has no baseURL to find the authorization server from${advice}`,
    )
    expect(await failing(hostWith({ settings: { baseURL: `${auth.origin}/v1?tenant=a` } }))).toBe(
      `the provider's baseURL has a query or fragment, so it can't name the API as a resource${advice}`,
    )
    expect(await failing(hostWith())).toBe("no provider named example is configured")
    const documents: Array<[(identifier: string) => unknown, string]> = [
      [() => ({ resource: "https://elsewhere.example", authorization_servers: [auth.issuer] }), "describes another resource"],
      [(identifier) => ({ resource: identifier }), "names no authorization server"],
      [(identifier) => ({ resource: identifier, authorization_servers: [auth.issuer, unsigned.issuer] }), "names more than one authorization server"],
      [naming(`${auth.issuer}?tenant=a`), "the API names an authorization server whose issuer the plugin can't use"],
      [naming(unsigned.issuer), "the authorization server the API names doesn't put its issuer in responses (RFC 9207)"],
      [naming(`${auth.origin}/missing`), "the authorization server the API names publishes no metadata"],
      [naming(impostor.issuer), "the authorization server the API names has metadata for another issuer"],
      [() => ["https://evil.example"], "the API has no valid resource metadata"],
      [(identifier) => ({ resource: identifier, authorization_servers: "https://evil.example" }), "the API's resource metadata has no valid authorization_servers"],
      [naming(incomplete.issuer), "the authorization server the API names has no valid token_endpoint"],
      [naming(fragmented.issuer), "the token_endpoint of the authorization server the API names cannot have a fragment"],
    ]
    for (const [document, message] of documents) {
      using llm = api(document)
      const error = await failing(hostWith({ settings: { baseURL: llm.identifier } }))
      expect(error).toContain(message)
      expect(error.endsWith(advice)).toBe(true)
      for (const named of [auth, unsigned, impostor, incomplete, fragmented]) expect(error).not.toContain(named.origin)
      expect(error).not.toContain("evil.example")
    }
    using missing = api(() => ({}), "/elsewhere")
    const unpublished = `${missing.identifier.replace("/elsewhere", "")}/v1`
    expect(await failing(hostWith({ settings: { baseURL: unpublished } }))).toBe(`the API's resource metadata answered 404${advice}`)
    expect(await failing(hostWith({ settings: { baseURL: "" } }))).toBe(`the provider's baseURL is empty${advice}`)
    // A redirect from the named server is refused without saying where it pointed.
    const redirecting = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => Response.redirect("https://elsewhere.example/", 302) })
    try {
      using llm = api(naming(`http://127.0.0.1:${redirecting.port}`))
      const error = await failing(hostWith({ settings: { baseURL: llm.identifier } }))
      expect(error).toBe(
        `the metadata of the authorization server the API names answered with a redirect, which the plugin does not follow${advice}`,
      )
    } finally {
      redirecting.stop(true)
    }
  })

  test("defaults scope to the API's scopes, refuses a list it can't request, and lets the options override both", async () => {
    using auth = identityProvider([bearer, bearer, bearer])
    const scopeOf = async (extra: Record<string, unknown>, set: Partial<Options> = {}) => {
      using llm = api(naming(auth.issuer, extra))
      const host = hostWith({ settings: { baseURL: llm.identifier } })
      const { url } = await Effect.runPromise(signIn({ ...options, ...set }, callback({ iss: auth.issuer }), host))
      return { scope: url.searchParams.get("scope"), resource: url.searchParams.get("resource") }
    }
    expect((await scopeOf({ scopes_supported: [] })).scope).toBeNull()
    using strict = authServer({
      metadata: () => ({ authorization_response_iss_parameter_supported: true, scopes_supported: [1, "offline_access"] }),
      tokens: [bearer],
    })
    using withoutOffline = api(naming(strict.issuer))
    const strictSignIn = signIn(options, callback({ iss: strict.issuer }), hostWith({ settings: { baseURL: withoutOffline.identifier } }))
    expect((await Effect.runPromise(strictSignIn)).url.searchParams.get("scope")).toBe("models:read")
    expect((await scopeOf({ scopes_supported: ["a", "a", "offline_access"] })).scope).toBe("a offline_access")
    const pinned = await scopeOf({ scopes_supported: ["bad scope"] }, { scope: "openid", resource: "urn:example:llm" })
    expect(pinned).toMatchObject({ scope: "openid", resource: "urn:example:llm" })
    for (const scopes of [["bad scope"], ["a".repeat(2049)], "models:read", null]) {
      using llm = api(naming(auth.issuer, { scopes_supported: scopes }))
      expect(await failing(hostWith({ settings: { baseURL: llm.identifier } }))).toBe(
        "the API lists scopes the plugin can't request; set the scope option",
      )
    }
  })

  test("needs a server that lists S256, from https when the API's document came over https", async () => {
    using auth = authServer({
      metadata: () => ({ authorization_response_iss_parameter_supported: true, code_challenge_methods_supported: undefined }),
    })
    using llm = api(naming(auth.issuer))
    expect(await failing(hostWith({ settings: { baseURL: llm.identifier } }))).toBe(
      `the authorization server the API names doesn't list PKCE with S256${advice}`,
    )
    const fetched = spyOn(globalThis, "fetch").mockResolvedValue(
      Response.json({ resource: "https://api.example/v1", authorization_servers: ["http://127.0.0.1:9"] }),
    )
    try {
      expect(await failing(hostWith({ settings: { baseURL: "https://api.example/v1" } }))).toBe(
        `the API names an authorization server whose issuer the plugin can't use${advice}`,
      )
    } finally {
      fetched.mockRestore()
    }
  })

  test("stops for an API that needs a token OpenCode can't send", async () => {
    using auth = identityProvider()
    const cases: Array<[Record<string, unknown>, string]> = [
      [{ dpop_bound_access_tokens_required: true }, "the API requires DPoP-bound access tokens, which OpenCode can't send"],
      [{ bearer_methods_supported: ["body"] }, "the API doesn't accept the access token in the Authorization header"],
      [{ bearer_methods_supported: [] }, "the API doesn't accept the access token in the Authorization header"],
    ]
    for (const [extra, message] of cases) {
      using llm = api(naming(auth.issuer, extra))
      expect(await failing(hostWith({ settings: { baseURL: llm.identifier } }))).toStartWith(message)
    }
    expect(auth.paths).toEqual([])
  })

  test("binds the provider to its last completed sign-in, and refuses another server before contacting it", async () => {
    using first = identityProvider([bearer, bearer])
    using second = identityProvider()
    using llm = api(naming(first.issuer))
    const stored = new Map<string, unknown>()
    const host = hostWith({ settings: { baseURL: llm.identifier }, storage: stored })
    // An attempt that never finishes binds nothing.
    await Effect.runPromise(Effect.scoped(registration(host, options).authorize({})))
    expect(stored.size).toBe(0)
    await Effect.runPromise(signInWith(host, first.issuer))
    await Effect.runPromise(signInWith(host, first.issuer))
    expect(stored.get("binding/example")).toBe(first.issuer)
    using moved = api(naming(second.issuer))
    expect(await failing(hostWith({ settings: { baseURL: moved.identifier }, storage: stored }))).toBe(
      "the API now names a different authorization server than this provider signed in with before; if that's expected" +
        advice.replace(";", ","),
    )
    expect(second.paths).toEqual([])
  })

  test("stores a configured issuer as the binding, and removes it for configured endpoints", async () => {
    using auth = authServer({ tokens: [bearer] })
    using tokens = tokenEndpoint([bearer])
    using llm = api(naming("https://unused.example"))
    const stored = new Map<string, unknown>([["binding/example", "https://old.example"]])
    const host = hostWith({ settings: { baseURL: llm.identifier }, storage: stored })
    await Effect.runPromise(signIn(auth.options, callback(), host))
    expect(stored.get("binding/example")).toBe(auth.issuer)
    await Effect.runPromise(signIn(optionsFor(tokens.url), callback(), host))
    expect(stored.has("binding/example")).toBe(false)
    expect(llm.paths).toEqual([])
  })

  test("keeps the binding when storing fails, and stops when it can't be read", async () => {
    using auth = identityProvider()
    using llm = api(naming(auth.issuer))
    const stored = new Map<string, unknown>()
    const settings = { baseURL: llm.identifier }
    const { credential } = await Effect.runPromise(signInWith(hostWith({ settings, storage: stored, failing: "set" }), auth.issuer))
    expect(credential.access).toBe("access")
    expect(stored.size).toBe(0)
    stored.set("binding/example", auth.issuer)
    const unreadable = `the plugin couldn't read which authorization server this provider signed in with before${advice}`
    expect(await failing(hostWith({ settings, storage: stored, failing: "get" }))).toBe(unreadable)
    expect(await failing(hostWith({ settings, storage: new Map([["binding/example", 42]]) }))).toBe(unreadable)
  })

  test("renews from the record without the API, and asks for a sign-in without one", async () => {
    using auth = identityProvider([bearer, bearer])
    let named = auth.issuer
    using llm = api((identifier) => naming(named)(identifier))
    const host = hostWith({ settings: { baseURL: llm.identifier } })
    const { credential } = await Effect.runPromise(signInWith(host, auth.issuer))
    // Even an API that now names another server doesn't move renewal.
    named = "https://elsewhere.example"
    const fetchedBefore = llm.paths.length
    const renewed = await Effect.runPromise(renew(registration(host, options), credential))
    expect(renewed.access).toBe("access")
    expect(llm.paths).toHaveLength(fetchedBefore)
    expect(auth.forms[1]).toMatchObject({ grant_type: "refresh_token", resource: llm.identifier })
    const unrecorded = credentialWith(`refresh-${crypto.randomUUID()}`)
    expect(await failure(renew(registration(host, options), unrecorded))).toBe(
      "the credential has no record of the server that issued it; sign in again",
    )
  })

  test("fetches the server's metadata afresh at each discovery sign-in, and renews with what it fetched", async () => {
    let tokenPath = "/token"
    using auth = authServer({
      metadata: (issuer) => ({
        authorization_response_iss_parameter_supported: true,
        token_endpoint: `${issuer}${tokenPath}`,
      }),
      tokens: [bearer],
    })
    using llm = api(naming(auth.issuer))
    const method = registration(hostWith({ settings: { baseURL: llm.identifier } }), options)
    const recorded = { "opencode-oauth": { issuer: auth.issuer } }
    await Effect.runPromise(renew(method, credentialWith(`refresh-${crypto.randomUUID()}`, recorded)))
    tokenPath = "/moved"
    await Effect.runPromise(Effect.scoped(method.authorize({})))
    await failure(renew(method, credentialWith(`refresh-${crypto.randomUUID()}`, recorded)))
    expect(auth.paths.filter((path) => path.includes("well-known"))).toHaveLength(2)
    expect(auth.paths.at(-1)).toBe("/moved")
  })

  test("keeps the named server out of a DNS failure and a refused code exchange", async () => {
    using unreachable = api(naming("https://auth.invalid"))
    const original = globalThis.fetch
    const fetched = spyOn(globalThis, "fetch").mockImplementation(((input: string | URL | Request, init?: RequestInit) =>
      String(input).startsWith("https://auth.invalid")
        ? Promise.reject(Object.assign(new TypeError("getaddrinfo ENOTFOUND auth.invalid"), { code: "ENOTFOUND" }))
        : original(input, init)) as typeof fetch)
    try {
      const error = await failing(hostWith({ settings: { baseURL: unreachable.identifier } }))
      expect(error).toBe(`the metadata of the authorization server the API names could not be reached${advice}`)
    } finally {
      fetched.mockRestore()
    }
    using refusing = identityProvider([{ status: 400, body: { error: "invalid_grant" } }])
    using llm = api(naming(refusing.issuer))
    const error = await failure(signInWith(hostWith({ settings: { baseURL: llm.identifier } }), refusing.issuer))
    expect(error).toBe('token endpoint answered 400: "invalid_grant"')
  })
})
