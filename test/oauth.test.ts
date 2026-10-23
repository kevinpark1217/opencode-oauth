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

const optionsFor =(tokenURL: string): Options => ({
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
    using tokens = tokenEndpoint([
      { status: 200, body: { access_token: "access", refresh_token: "refresh", expires_in: 900, token_type: "Bearer" } },
    ])
    const before = Date.now()
    const { url, credential, page } = await Effect.runPromise(
      signIn(optionsFor(tokens.url), (url) =>
        fetch(`${redirectOf(url)}?code=the-code&state=${url.searchParams.get("state")}`),
      ),
    )

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

  test("adds authorizationParams to the authorization request", async () => {
    using tokens = tokenEndpoint([{ status: 200, body: { access_token: "access", refresh_token: "r", expires_in: 900 } }])
    const options = { ...optionsFor(tokens.url), authorizationParams: { audience: "https://api.example" } }
    const { url } = await Effect.runPromise(
      signIn(options, (url) => fetch(`${redirectOf(url)}?code=the-code&state=${url.searchParams.get("state")}`)),
    )
    expect(url.searchParams.get("audience")).toBe("https://api.example")
    expect(url.searchParams.get("response_type")).toBe("code")
  })

  test("listens on a fixed port when one is set", async () => {
    using tokens = tokenEndpoint([{ status: 200, body: { access_token: "access", refresh_token: "r", expires_in: 900 } }])
    const probe = Bun.serve({ hostname: "127.0.0.1", port: 0, fetch: () => new Response() })
    const port = probe.port
    probe.stop(true)
    const { url } = await Effect.runPromise(
      signIn({ ...optionsFor(tokens.url), port }, (url) =>
        fetch(`${redirectOf(url)}?code=the-code&state=${url.searchParams.get("state")}`),
      ),
    )
    expect(redirectOf(url)).toBe(`http://127.0.0.1:${port}/callback`)
  })

  test("refuses a callback with another state, and still finishes with the real one", async () => {
    using tokens = tokenEndpoint([{ status: 200, body: { access_token: "access", refresh_token: "r", expires_in: 900 } }])
    const statuses: number[] = []
    const { credential } = await Effect.runPromise(
      signIn(optionsFor(tokens.url), async (url) => {
        for (const query of ["code=stolen&state=forged", "error=access_denied&error_description=Phish"]) {
          statuses.push((await fetch(`${redirectOf(url)}?${query}`)).status)
        }
        return fetch(`${redirectOf(url)}?code=the-code&state=${url.searchParams.get("state")}`)
      }),
    )
    expect(statuses).toEqual([400, 400])
    expect(tokens.forms.map((form) => form.code)).toEqual(["the-code"])
    expect(credential.access).toBe("access")
  })

  test("reports the authorization server's error for this attempt", async () => {
    using tokens = tokenEndpoint([])
    const error = await Effect.runPromise(
      Effect.flip(
        signIn(optionsFor(tokens.url), (url) =>
          fetch(
            `${redirectOf(url)}?error=access_denied&error_description=The+user+denied+consent&state=${url.searchParams.get("state")}`,
          ),
        ),
      ),
    )
    expect(String(error)).toContain("The user denied consent")
    expect(tokens.forms).toHaveLength(0)
  })

  test("answers other paths with 404 and a second callback with 409", async () => {
    using tokens = tokenEndpoint([{ status: 200, body: { access_token: "access", refresh_token: "r", expires_in: 900 } }])
    let other = 0
    let second: Promise<Response> | undefined
    const { page } = await Effect.runPromise(
      signIn(optionsFor(tokens.url), async (url) => {
        other = (await fetch(new URL("/elsewhere", redirectOf(url)))).status
        const callback = `${redirectOf(url)}?code=the-code&state=${url.searchParams.get("state")}`
        const first = fetch(callback)
        second = fetch(callback)
        return first
      }),
    )
    expect(other).toBe(404)
    expect([page.status, (await second)?.status].sort()).toEqual([200, 409])
  })

  test("fails when the server issues no refresh token", async () => {
    using tokens = tokenEndpoint([{ status: 200, body: { access_token: "access", expires_in: 900 } }])
    const error = await Effect.runPromise(
      Effect.flip(
        signIn(optionsFor(tokens.url), (url) =>
          fetch(`${redirectOf(url)}?code=the-code&state=${url.searchParams.get("state")}`),
        ),
      ),
    )
    expect(String(error)).toContain("no refresh token")
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
    using tokens = tokenEndpoint([{ status: 200, body: { access_token: "new-access", expires_in: 900 } }])
    const refresh = `refresh-${crypto.randomUUID()}`
    const next = await Effect.runPromise(
      registration(optionsFor(tokens.url)).refresh?.(credentialWith(refresh)) ?? Effect.die("no refresh"),
    )
    expect(tokens.forms).toEqual([{ grant_type: "refresh_token", refresh_token: refresh, client_id: "opencode" }])
    expect(next).toMatchObject({ access: "new-access", refresh })
  })

  test("sends one request for concurrent and later refreshes of the same token", async () => {
    using tokens = tokenEndpoint([
      { status: 200, body: { access_token: "new-access", refresh_token: "rotated", expires_in: 900 } },
    ])
    const method = registration(optionsFor(tokens.url))
    const current = credentialWith(`refresh-${crypto.randomUUID()}`)
    const run = () => Effect.runPromise(method.refresh?.(current) ?? Effect.die("no refresh"))
    const [first, second] = await Promise.all([run(), run()])
    const late = await run()
    expect(tokens.forms).toHaveLength(1)
    expect(second).toEqual(first)
    expect(late).toEqual(first)
    expect(first.refresh).toBe("rotated")
  })

  test("asks again when the server did not rotate the refresh token", async () => {
    using tokens = tokenEndpoint([
      { status: 200, body: { access_token: "first", expires_in: 900 } },
      { status: 200, body: { access_token: "second", expires_in: 900 } },
    ])
    const method = registration(optionsFor(tokens.url))
    const current = credentialWith(`refresh-${crypto.randomUUID()}`)
    const run = () => Effect.runPromise(method.refresh?.(current) ?? Effect.die("no refresh"))
    expect((await run()).access).toBe("first")
    expect((await run()).access).toBe("second")
    expect(tokens.forms).toHaveLength(2)
  })

  test("does not follow a redirect with the refresh token", async () => {
    using elsewhere = tokenEndpoint([])
    using tokens = tokenEndpoint([new Response(null, { status: 307, headers: { Location: elsewhere.url } })])
    const current = credentialWith(`refresh-${crypto.randomUUID()}`)
    const error = await Effect.runPromise(
      Effect.flip(registration(optionsFor(tokens.url)).refresh?.(current) ?? Effect.die("no refresh")),
    )
    expect(error).toBeInstanceOf(Error)
    expect(tokens.forms).toHaveLength(1)
    expect(elsewhere.forms).toHaveLength(0)
  })

  test("rejects a success that carries no token", async () => {
    using tokens = tokenEndpoint([new Response("<html>login</html>", { status: 200 })])
    const current = credentialWith(`refresh-${crypto.randomUUID()}`)
    const error = await Effect.runPromise(
      Effect.flip(registration(optionsFor(tokens.url)).refresh?.(current) ?? Effect.die("no refresh")),
    )
    expect(String(error)).toContain("no usable access token")
  })

  test("fails with the OAuth error code, and retries on the next attempt", async () => {
    using tokens = tokenEndpoint([
      { status: 400, body: { error: "invalid_grant", error_description: "do not echo" } },
      { status: 200, body: { access_token: "new-access", expires_in: 900 } },
    ])
    const method = registration(optionsFor(tokens.url))
    const current = credentialWith(`refresh-${crypto.randomUUID()}`)
    const error = await Effect.runPromise(Effect.flip(method.refresh?.(current) ?? Effect.die("no refresh")))
    expect(String(error)).toContain("400 (invalid_grant)")
    expect(String(error)).not.toContain("do not echo")
    const next = await Effect.runPromise(method.refresh?.(current) ?? Effect.die("no refresh"))
    expect(next.access).toBe("new-access")
    expect(tokens.forms).toHaveLength(2)
  })
})
