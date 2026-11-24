import type { SchemaIssue } from "effect"

// Server text reaches an error message only when it is short and fits OAuth's
// error grammar: printable ASCII without `"` or `\` (RFC 6749 appendix A.7, A.8).
export const quotable = (value: unknown, max = 64): value is string =>
  typeof value === "string" && value.length <= max && /^[\x20-\x21\x23-\x5B\x5D-\x7E]+$/.test(value)

// Returns only the schema's own field names, never text from the response.
export function failedField(issue: SchemaIssue.Issue, fields: ReadonlyArray<string>): string | undefined {
  switch (issue._tag) {
    case "Pointer": {
      const [field] = issue.path
      return typeof field === "string" && fields.includes(field) ? field : undefined
    }
    case "Composite":
      return issue.issues.map((inner) => failedField(inner, fields)).find((field) => field !== undefined)
    default:
      return undefined
  }
}

export const toError = (cause: unknown) => (cause instanceof Error ? cause : new Error(String(cause)))
