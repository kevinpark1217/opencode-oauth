import { Schema } from "effect"
import { endpointProblem, issuerProblem, resourceProblem, urlProblem } from "./url.js"

const OptionsSchema = Schema.Struct({
  provider: Schema.NonEmptyString,
  clientID: Schema.NonEmptyString,
  issuer: Schema.optional(Schema.NonEmptyString),
  authorizationEndpoint: Schema.optional(Schema.NonEmptyString),
  tokenEndpoint: Schema.optional(Schema.NonEmptyString),
  // OpenCode turns an unset {env:…} into an empty string, which stays an error.
  scope: Schema.optional(Schema.NonEmptyString),
  resource: Schema.optional(Schema.NonEmptyString),
  port: Schema.optional(Schema.Int.check(Schema.isBetween({ minimum: 0, maximum: 65535 }))),
  authorizationParams: Schema.optional(Schema.Record(Schema.String, Schema.String)),
  searchURL: Schema.optional(Schema.NonEmptyString),
  discoverModels: Schema.optional(Schema.Boolean),
})
export type Options = typeof OptionsSchema.Type

const reservedParams = [
  "response_type",
  "client_id",
  "redirect_uri",
  "scope",
  "state",
  "code_challenge",
  "code_challenge_method",
]

export function parseOptions(input: unknown): Options {
  const options = Schema.decodeUnknownSync(OptionsSchema, { onExcessProperty: "error" })(input)
  const check = (name: string, value: string | undefined, problemOf: (value: string) => string | undefined) => {
    const problem = value === undefined ? undefined : problemOf(value)
    if (problem !== undefined) throw new Error(`${name} ${problem}`)
  }
  check("issuer", options.issuer, issuerProblem)
  check("authorizationEndpoint", options.authorizationEndpoint, endpointProblem)
  check("tokenEndpoint", options.tokenEndpoint, endpointProblem)
  check("searchURL", options.searchURL, urlProblem)
  if (options.issuer !== undefined) {
    if (options.authorizationEndpoint !== undefined || options.tokenEndpoint !== undefined) {
      throw new Error("set issuer, or authorizationEndpoint and tokenEndpoint, not both")
    }
  } else if (options.authorizationEndpoint === undefined || options.tokenEndpoint === undefined) {
    throw new Error("set issuer, or both authorizationEndpoint and tokenEndpoint")
  }
  check("resource", options.resource, resourceProblem)
  for (const key of Object.keys(options.authorizationParams ?? {})) {
    if (key === "resource") throw new Error("set resource as an option of its own, not in authorizationParams")
    if (reservedParams.includes(key)) throw new Error(`authorizationParams cannot set ${key}`)
  }
  return options
}
