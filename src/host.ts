// OpenCode before 2.2.1 merges a credential's metadata into its provider's
// settings, and an AI SDK package then sends those with every chat request.
export const minimumOpenCode = "2.2.1"

// OpenCode doesn't check a plugin's peer range. Only release numbers are
// compared: preview builds (0.0.0-<channel>-<n>), local and unknown load.
export function checkHost(version: string) {
  const parts = /^(\d+)\.(\d+)\.(\d+)$/.exec(version)?.slice(1).map(Number)
  if (parts === undefined) return
  const minimum = minimumOpenCode.split(".").map(Number)
  const differs = parts.findIndex((part, index) => part !== minimum[index])
  if (differs === -1 || parts[differs]! > minimum[differs]!) return
  throw new Error(
    `needs OpenCode ${minimumOpenCode} or later; this host reports ${version}. ` +
      "An earlier release from https://github.com/kevinpark1217/opencode-oauth/releases supports older OpenCode, " +
      `but a credential signed in or renewed with this release on OpenCode ${minimumOpenCode} or later needs a new sign-in there.`,
  )
}
