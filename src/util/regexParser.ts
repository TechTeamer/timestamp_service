function parseRegex<Groups extends number | (string | number)[] | undefined, ReviveResult>(
  text: string,
  regex: RegExp,
  groups: Groups,
  revive: (
    parameter: Groups extends number
      ? string
      : Groups extends (string | number)[]
        ? Record<string | number, string>
        : RegExpMatchArray
  ) => ReviveResult = value => value as unknown as ReviveResult
): ReviveResult | null | undefined {
  const result = text.match(regex)
  if (!result) {
    return null
  }

  if (!groups) {
    return (revive as (parameter: RegExpMatchArray) => ReviveResult)(result)
  }

  if (typeof groups === 'number') {
    return (revive as (parameter: string) => ReviveResult)(result[groups])
  }

  if (Array.isArray(groups)) {
    const ret: Record<string | number, string> = {}
    groups.forEach((name, i) => {
      ret[name] = result[i + 1]
    })
    return (revive as (parameter: Record<string | number, string>) => ReviveResult)(ret)
  }
}

function createParser<ReviveResult = unknown>(
  regex: RegExp,
  groups: number | number[],
  revive: (value: unknown) => ReviveResult
): (text: string) => ReviveResult | null | undefined {
  return (text: string) => {
    return parseRegex(text, regex, groups, revive)
  }
}

export { createParser as create }
export { parseRegex }
