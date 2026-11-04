import { Effect } from "effect"

export function getJSON(url: URL, accessToken: string, what: string, timeoutMs: number) {
  return Effect.tryPromise({
    try: async (signal) => {
      const response = await fetch(url, {
        headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" },
        // The token goes to this URL only.
        redirect: "error",
        signal: AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)]),
      })
      if (!response.ok) throw new Error(`${what} answered ${response.status}`)
      return (await response.json().catch(() => undefined)) as unknown
    },
    catch: (cause) =>
      cause instanceof Error && cause.name === "TimeoutError"
        ? new Error(`${what} did not answer within ${timeoutMs / 1000} s`)
        : cause instanceof Error
          ? cause
          : new Error(String(cause)),
  })
}
