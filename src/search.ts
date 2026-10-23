// Web search through a SearXNG that accepts the provider's access token.
import { Effect, Schema } from "effect"

const SearxngResponse = Schema.Struct({ results: Schema.Array(Schema.Unknown) })

// Checked one by one: a result an engine filled oddly is dropped, not the search.
const SearxngResult = Schema.Struct({
  url: Schema.String,
  title: Schema.optional(Schema.NullOr(Schema.String)),
  content: Schema.optional(Schema.NullOr(Schema.String)),
  publishedDate: Schema.optional(Schema.NullOr(Schema.String)),
})
const isResult = Schema.is(SearxngResult)

// SearXNG prints dates without a zone; read as UTC, not this machine's time.
const parseDate = (value: string) => Date.parse(/(Z|[+-]\d\d:?\d\d)$/.test(value) ? value : `${value}Z`)

export interface SearchResult {
  readonly url: string
  readonly title?: string
  readonly content?: string
  readonly time: { readonly published?: number }
}

// What OpenCode's built-in providers ask for.
const maxResults = 8
const searchTimeoutMs = 25_000

// The query and the token cross to `searchURL` only: no redirect is followed.
// Errors carry the HTTP status, never a body.
export function search(searchURL: string, query: string, accessToken: string) {
  return Effect.tryPromise({
    try: async (signal) => {
      const url = new URL(searchURL)
      url.searchParams.set("q", query)
      url.searchParams.set("format", "json")
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
        redirect: "error",
        signal: AbortSignal.any([signal, AbortSignal.timeout(searchTimeoutMs)]),
      })
      if (!response.ok) throw new Error(`search answered ${response.status}`)
      return (await response.json().catch(() => undefined)) as unknown
    },
    catch: (cause) =>
      cause instanceof Error && cause.name === "TimeoutError"
        ? new Error(`search did not answer within ${searchTimeoutMs / 1000} s`)
        : cause instanceof Error
          ? cause
          : new Error(String(cause)),
  }).pipe(
    Effect.flatMap((body) =>
      Schema.decodeUnknownEffect(SearxngResponse)(body).pipe(
        Effect.mapError(() => new Error("search returned no usable results")),
      ),
    ),
    Effect.map(({ results }) =>
      results
        .filter(isResult)
        .slice(0, maxResults)
        .map((item): SearchResult => {
          const published = item.publishedDate ? parseDate(item.publishedDate) : Number.NaN
          return {
            url: item.url,
            ...(item.title ? { title: item.title } : {}),
            ...(item.content ? { content: item.content } : {}),
            time: Number.isFinite(published) ? { published } : {},
          }
        }),
    ),
  )
}
