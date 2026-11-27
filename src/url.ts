// What the plugin accepts as a URL. Each check returns what's wrong, worded to
// follow the URL's name, or undefined.

const secureRule = "must be an https URL with a host and no user name, password or whitespace"

// Codes and tokens cross these; plain http is accepted only to this machine, and
// only from a document fetched over http. The raw string is read because the
// parser drops whitespace and extra slashes before the host, and an empty user name.
export function urlProblem(value: string, namedBy?: string): string | undefined {
  const authority = /^https?:\/\/([^/\\?#]*)/i.exec(value)?.[1]
  if (!authority || authority.includes("@") || /[\x00-\x20\x7f]/.test(value)) return secureRule
  const url = URL.parse(value)
  if (url?.protocol === "https:") return undefined
  const local = url?.protocol === "http:" && (url.hostname === "127.0.0.1" || url.hostname === "[::1]")
  return local && (namedBy === undefined || URL.parse(namedBy)?.protocol === "http:") ? undefined : secureRule
}

// RFC 8414 section 2.
export function issuerProblem(value: string, namedBy?: string): string | undefined {
  return urlProblem(value, namedBy) ?? (/[?#]/.test(value) ? "cannot have a query or fragment" : undefined)
}

// RFC 6749 sections 3.1 and 3.2.
export function endpointProblem(value: string, namedBy?: string): string | undefined {
  return urlProblem(value, namedBy) ?? (value.includes("#") ? "cannot have a fragment" : undefined)
}

// RFC 8707 section 2.
export function resourceProblem(value: string): string | undefined {
  return URL.parse(value) === null || /[\s#]/.test(value) ? "must be an absolute URI without a fragment" : undefined
}
