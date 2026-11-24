import { Effect } from "effect"
import { brotliDecompress, gunzip, inflate, zstdDecompress } from "node:zlib"

// Far above any real response; OpenRouter's model list is about 0.9 MB.
const maxBody = 4 * 1024 * 1024

// Asks for an uncompressed body and takes any body as sent: Bun inflates a
// compressed one in full even after the reader stops, so a few KB of brotli
// could take gigabytes. `decompress` is Bun's own option.
function request(url: string | URL, init: RequestInit) {
  const headers = new Headers(init.headers)
  headers.set("Accept-Encoding", "identity")
  return fetch(url, { ...init, headers, decompress: false })
}

type Decoder = (
  body: Buffer,
  options: { maxOutputLength: number },
  callback: (error: Error | null, result: Buffer) => void,
) => void

// Asynchronous, so a body crafted to decode slowly doesn't stall OpenCode.
const decoding = (decoder: Decoder) => (body: Buffer) =>
  new Promise<Buffer>((resolve, reject) =>
    decoder(body, { maxOutputLength: maxBody }, (error, result) => (error ? reject(error) : resolve(result))),
  )
const decoders = new Map([
  ["gzip", decoding(gunzip)],
  ["x-gzip", decoding(gunzip)],
  ["deflate", decoding(inflate)],
  ["br", decoding(brotliDecompress)],
  ["zstd", decoding(zstdDecompress)],
])

type Refusal = "too large" | "undecodable"

// Counts the body as it arrives, so a huge or endless one is cut off rather than
// held whole (leaving the loop cancels the rest), and decodes it with the same
// limit on what it decodes to. Servers code a body once at most, so one coded
// more than once is refused rather than decoded layer by layer.
async function readBody(response: Response): Promise<{ readonly text: string } | { readonly refused: Refusal }> {
  const codings = (response.headers.get("content-encoding") ?? "")
    .split(",")
    .map((coding) => coding.trim().toLowerCase())
    .filter((coding) => coding !== "" && coding !== "identity")
  const decode = codings.length === 1 ? decoders.get(codings[0]!) : undefined
  if (codings.length > 0 && decode === undefined) {
    await response.body?.cancel()
    return { refused: "undecodable" }
  }
  const chunks: Uint8Array[] = []
  let size = 0
  for await (const chunk of response.body ?? []) {
    size += chunk.byteLength
    if (size > maxBody) return { refused: "too large" }
    chunks.push(chunk)
  }
  let body: Buffer = Buffer.concat(chunks)
  if (decode !== undefined) {
    try {
      body = await decode(body)
    } catch (error) {
      return { refused: (error as { code?: unknown }).code === "ERR_BUFFER_TOO_LARGE" ? "too large" : "undecodable" }
    }
  }
  return { text: new TextDecoder().decode(body) }
}

const parseJSON = (text: string): unknown => {
  try {
    return JSON.parse(text)
  } catch {
    return undefined
  }
}

// Starts when created, so requests made under one share its time.
export const deadline = (ms: number) => ({ signal: AbortSignal.timeout(ms), seconds: ms / 1000 })
type Deadline = ReturnType<typeof deadline>

// A status carries only the body's OAuth error code (RFC 6749 section 5.2),
// never the rest of the body; the caller decides whether to quote it.
export type Failure =
  | { readonly reason: "status"; readonly status: number; readonly error: string | undefined }
  | { readonly reason: "timeout"; readonly seconds: number }
  | { readonly reason: Refusal | "redirect" | "not JSON" | "untrusted" | "invalid certificate" | "unreachable" }

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

const isRedirect = (status: number) => status >= 300 && status < 400

// Every request the plugin makes. It reports a failure by its kind, never with
// the runtime's message, which names the host. A redirect is refused by its
// status, so a code or token in the request never goes to its target. An error's
// body is read only for its code, so a broken, oversized or undecodable one
// still reports the status.
export function fetchJSON(url: string | URL, init: RequestInit, within: Deadline): Effect.Effect<unknown, Failure> {
  return Effect.tryPromise({
    try: async (signal): Promise<{ readonly body: unknown } | Failure> => {
      const response = await request(url, { ...init, redirect: "manual", signal: AbortSignal.any([signal, within.signal]) })
      if (isRedirect(response.status)) return { reason: "redirect" }
      if (!response.ok) {
        const read = await readBody(response).catch(() => undefined)
        const body = read !== undefined && "text" in read ? parseJSON(read.text) : undefined
        const error = (body as { error?: unknown } | null | undefined)?.error
        return { reason: "status", status: response.status, error: typeof error === "string" ? error : undefined }
      }
      const read = await readBody(response)
      if ("refused" in read) return { reason: read.refused }
      const body = parseJSON(read.text)
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
    case "too large":
      return `answered with more than ${maxBody / 1024 / 1024} MiB`
    case "undecodable":
      return "answered with a body the plugin can't decode"
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
