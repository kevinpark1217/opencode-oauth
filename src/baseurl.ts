import { urlProblem } from "./url.js"

// A provider's baseURL as OpenCode sends requests to it: ${NAME} filled as its
// prepareProviderURL fills it, then trailing slashes stripped as its trimBaseUrl
// does, and held to the plugin's URL rules, since the token goes there.
// ${AWS_REGION} takes a region setting, as OpenCode does since 2.2.0, so the
// plugin calls the same host OpenCode does. It returns a reason rather than
// throwing, because a throw in a model transform disables the whole plugin.
export function readBaseURL(
  settings: Readonly<Record<string, unknown>> | undefined,
): { readonly url: string } | { readonly problem: string } | undefined {
  const baseURL = settings?.baseURL
  if (typeof baseURL !== "string") return undefined
  if (baseURL === "") return { problem: "the provider's baseURL is empty" }
  const filled = baseURL.replace(/\$\{([^}]+)\}/g, (placeholder, name: string) => {
    const value = name === "AWS_REGION" && typeof settings?.region === "string" ? settings.region : process.env[name]
    return value ?? placeholder
  })
  const left = new Set(Array.from(filled.matchAll(/\$\{[^}]+\}/g), ([placeholder]) => placeholder))
  if (left.size > 0) return { problem: `the provider's baseURL leaves ${[...left].join(", ")} unfilled` }
  const url = filled.replace(/\/+$/, "")
  const problem = urlProblem(url)
  return problem === undefined ? { url } : { problem: `the provider's baseURL ${problem}` }
}
