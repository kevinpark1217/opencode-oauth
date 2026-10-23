import { describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { search } from "../src/search.js"

// A SearXNG that records each request's URL and bearer, and answers with
// `respond`'s response.
function searxng(respond: () => Response) {
  const requests: Array<{ url: string; authorization: string | null }> = []
  const server = Bun.serve({
    hostname: "127.0.0.1",
    port: 0,
    fetch(request) {
      requests.push({ url: request.url, authorization: request.headers.get("authorization") })
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
    await Effect.runPromise(Effect.flip(search(stub.url, "q", "access-token")))
    expect(elsewhere.requests).toHaveLength(0)
  })

  test("rejects a success that is not SearXNG's JSON", async () => {
    using stub = searxng(() => new Response("<html>search page</html>", { status: 200 }))
    const error = await Effect.runPromise(Effect.flip(search(stub.url, "q", "access-token")))
    expect(error.message).toBe("search returned no usable results")
  })
})
