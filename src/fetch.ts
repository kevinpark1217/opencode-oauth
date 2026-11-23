import { Effect } from "effect"

// Starts when created, so requests made under one share its time.
export const deadline = (ms: number) => ({ signal: AbortSignal.timeout(ms), seconds: ms / 1000 })
type Deadline = ReturnType<typeof deadline>

// A status carries only the body's OAuth error code (RFC 6749 section 5.2),
// never the rest of the body; the caller decides whether to quote it.
export type Failure =
  | { readonly reason: "status"; readonly status: number; readonly error: string | undefined }
  | { readonly reason: "timeout"; readonly seconds: number }
  | { readonly reason: "redirect" | "not JSON" | "untrusted" | "invalid certificate" | "unreachable" }

// What a private CA's certificate fails with, by OpenSSL's names. Bun puts the
// code on the error, Node on its cause.
const untrustedCodes = new Set([
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "UNABLE_TO_GET_ISSUER_CERT",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
])

const codeOf = (cause: unknown): unknown => (cause as { code?: unknown } | undefined)?.code

function classify(cause: unknown, { seconds }: Deadline): Failure {
  if (cause instanceof Error && cause.name === "TimeoutError") return { reason: "timeout", seconds }
  const code = codeOf(cause) ?? codeOf((cause as { cause?: unknown } | undefined)?.cause)
  if (typeof code !== "string") return { reason: "unreachable" }
  if (untrustedCodes.has(code)) return { reason: "untrusted" }
  // Such as CERT_HAS_EXPIRED or ERR_TLS_CERT_ALTNAME_INVALID.
  return { reason: /CERT|HOSTNAME_MISMATCH/.test(code) ? "invalid certificate" : "unreachable" }
}

const parseJSON = (text: string): unknown => {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}

const isRedirect = (status: number) => status >= 300 && status < 400

// Every request the plugin makes. It reports a failure by its kind, never with
// the runtime's message, which names the host. A redirect is refused by its
// status, so a code or token in the request never goes to its target. An error's
// body is read only for its code, so a broken one still reports the status.
export function fetchJSON(url: string | URL, init: RequestInit, within: Deadline): Effect.Effect<unknown, Failure> {
  return Effect.tryPromise({
    try: async (signal): Promise<{ readonly body: unknown } | Failure> => {
      const response = await fetch(url, { ...init, redirect: "manual", signal: AbortSignal.any([signal, within.signal]) })
      if (isRedirect(response.status)) return { reason: "redirect" }
      if (!response.ok) {
        const error = (parseJSON(await response.text().catch(() => "")) as { error?: unknown } | null | undefined)?.error
        return { reason: "status", status: response.status, error: typeof error === "string" ? error : undefined }
      }
      const body = parseJSON(await response.text())
      return body === undefined ? { reason: "not JSON" } : { body }
    },
    catch: (cause) => classify(cause, within),
  }).pipe(Effect.flatMap((result) => ("reason" in result ? Effect.fail(result) : Effect.succeed(result.body))))
}

// /models and search, which carry the access token.
export function getJSON(url: URL, accessToken: string, what: string, timeoutMs: number) {
  return Effect.suspend(() =>
    fetchJSON(url, { headers: { Authorization: `Bearer ${accessToken}`, Accept: "application/json" } }, deadline(timeoutMs)),
  ).pipe(Effect.mapError((failure) => new Error(`${what} ${explain(failure)}`)))
}

export function explain(failure: Failure): string {
  switch (failure.reason) {
    case "status":
      return `answered ${failure.status}`
    case "timeout":
      return `did not answer within ${failure.seconds} s`
    case "redirect":
      return "answered with a redirect, which the plugin does not follow"
    case "not JSON":
      return "did not answer with JSON"
    case "untrusted":
      return "has a certificate that isn't trusted; for a private CA, set NODE_EXTRA_CA_CERTS to its certificate file"
    case "invalid certificate":
      return "has an invalid certificate, such as an expired one or one for another name"
    case "unreachable":
      return "could not be reached"
  }
}
