import { describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { search } from "../src/search.js"

// A SearXNG that records each request's URL and bearer, and answers with
// `respond`'s response.
function searxng(respond: () => Response) {
  const requests: Array<{ url: string; authorization: string | null; encoding: string | null }> = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      const { headers } = request
      requests.push({ url: request.url, authorization: headers.get("authorization"), encoding: headers.get("accept-encoding") })
      return respond()
    },
  })
  return { url: `http://127.0.0.1:${server.port}/search`, requests, [Symbol.dispose]: () => server.stop(true) }
}

const result = (n: number, extra: Record<string, unknown> = {}) => ({
  url: `https://example.org/${n}`,
  title: `Result ${n}`,
  content: `About ${n}`,
  publishedDate: null,
  engine: "wikipedia",
  ...extra,
})

describe("search", () => {
  test("sends the query and the token, and keeps eight results in OpenCode's shape", async () => {
    using stub = searxng(() =>
      Response.json({
        query: "q",
        results: [
          result(0, { publishedDate: "2026-06-13T06:39:10" }),
          result(1, { title: "", content: "" }),
          ...Array.from({ length: 10 }, (_, i) => result(i + 2)),
        ],
      }),
    )
    const results = await Effect.runPromise(search(stub.url, "oauth pkce", "access-token"))

    const sent = new URL(stub.requests[0]?.url ?? "")
    expect(sent.searchParams.get("q")).toBe("oauth pkce")
    expect(sent.searchParams.get("format")).toBe("json")
    expect(stub.requests[0]?.authorization).toBe("Bearer access-token")
    expect(results).toHaveLength(8)
    expect(results[0]).toEqual({
      url: "https://example.org/0",
      title: "Result 0",
      content: "About 0",
      time: { published: Date.UTC(2026, 5, 13, 6, 39, 10) },
    })
    expect(results[1]).toEqual({ url: "https://example.org/1", time: {} })
  })

  test("drops a result without a URL, keeps null fields out, and honours a zone", async () => {
    using stub = searxng(() =>
      Response.json({
        results: [
          { title: "No URL" },
          { url: "https://example.org/a", title: null, content: null, publishedDate: "2026-06-13T06:39:10+02:00" },
        ],
      }),
    )
    const results = await Effect.runPromise(search(stub.url, "q", "access-token"))
    expect(results).toEqual([{ url: "https://example.org/a", time: { published: Date.UTC(2026, 5, 13, 4, 39, 10) } }])
  })

  test("fails with the HTTP status, never the body", async () => {
    using stub = searxng(() => new Response("secret page", { status: 403 }))
    const error = await Effect.runPromise(Effect.flip(search(stub.url, "q", "access-token")))
    expect(error.message).toBe("search answered 403")
  })

  test("does not follow a redirect with the token", async () => {
    using elsewhere = searxng(() => Response.json({ results: [] }))
    using stub = searxng(() => Response.redirect(elsewhere.url, 302))
    const error = await Effect.runPromise(Effect.flip(search(stub.url, "q", "access-token")))
    expect(error.message).toBe("search answered with a redirect, which the plugin does not follow")
    expect(elsewhere.requests).toHaveLength(0)
  })

  test("refuses a response over 4 MiB", async () => {
    using stub = searxng(() => Response.json({ results: [result(0, { content: "a".repeat(4 * 1024 * 1024) })] }))
    const error = await Effect.runPromise(Effect.flip(search(stub.url, "q", "access-token")))
    expect(error.message).toBe("search answered with more than 4 MiB")
  })

  test("asks for an uncompressed body, reads a compressed one, and refuses one coded twice", async () => {
    const body = JSON.stringify({ results: [result(0)] })
    const responses = [
      new Response(Bun.gzipSync(body), { headers: { "Content-Encoding": "gzip" } }),
      new Response(Bun.gzipSync(Bun.gzipSync(body)), { headers: { "Content-Encoding": "gzip, gzip" } }),
    ]
    using stub = searxng(() => responses.shift() ?? new Response(null, { status: 500 }))
    expect(await Effect.runPromise(search(stub.url, "q", "access-token"))).toHaveLength(1)
    const error = await Effect.runPromise(Effect.flip(search(stub.url, "q", "access-token")))
    expect(error.message).toBe("search answered with a body the plugin can't decode")
    expect(stub.requests.map((request) => request.encoding)).toEqual(["identity", "identity"])
  })

  test("rejects a success that is not SearXNG's JSON", async () => {
    const responses = [new Response("<html>search page</html>", { status: 200 }), Response.json({ hits: [] })]
    using stub = searxng(() => responses.shift() ?? new Response(null, { status: 500 }))
    for (const message of ["search did not answer with JSON", "search returned no usable results"]) {
      const error = await Effect.runPromise(Effect.flip(search(stub.url, "q", "access-token")))
      expect(error.message).toBe(message)
    }
  })
})
