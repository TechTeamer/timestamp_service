/**
 * @param text {string}
 * @param regex {RegExp}
 * @param groups {number | number[]}
 * @param revive {(value: any) => any}
 * @returns {any|null}
 */
function parseRegex (text, regex, groups, revive) {
  const result = text.match(regex)
  if (!result) {
    return null
  }

  revive = revive || (value => value)

  if (!groups) {
    return revive(result)
  }

  if (typeof groups === 'number') {
    return revive(result[groups])
  }

  if (Array.isArray(groups)) {
    const ret = {}
    groups.forEach((name, i) => {
      ret[name] = result[i + 1]
    })
    return revive(ret)
  }
}

function createParser (regex, groups, revive) {
  return (text) => {
    return parseRegex(text, regex, groups, revive)
  }
}

export { createParser as create }
export { parseRegex }
