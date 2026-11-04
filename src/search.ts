import { Effect, Schema } from "effect"
import { getJSON } from "./fetch.js"

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

interface SearchResult {
  readonly url: string
  readonly title?: string
  readonly content?: string
  readonly time: { readonly published?: number }
}

// What OpenCode's built-in providers ask for.
const maxResults = 8
const searchTimeoutMs = 25_000

export function search(searchURL: string, query: string, accessToken: string) {
  const url = new URL(searchURL)
  url.searchParams.set("q", query)
  url.searchParams.set("format", "json")
  return getJSON(url, accessToken, "search", searchTimeoutMs).pipe(
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
