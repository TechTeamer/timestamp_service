declare function parseRegex<Groups extends number | (string | number)[] | undefined, ReviveResult>(text: string, regex: RegExp, groups: Groups, revive?: (parameter: Groups extends number ? string : Groups extends (string | number)[] ? Record<string | number, string> : RegExpMatchArray) => ReviveResult): ReviveResult | null | undefined;
declare function createParser<ReviveResult = unknown>(regex: RegExp, groups: number | number[], revive: (value: unknown) => ReviveResult): (text: string) => ReviveResult | null | undefined;
export { createParser as create };
export { parseRegex };
