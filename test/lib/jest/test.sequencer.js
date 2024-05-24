const path = require('path')
// eslint-disable-next-line n/no-unpublished-require
const { default: BaseTestSequencer } = require('@jest/test-sequencer')

const e2e = testNames => testNames.map(name => `e2e/${name}`)
const unit = testNames => testNames.map(name => `unit/${name}`)
const integration = testNames => testNames.map(name => `integration/${name}`)
const regression = testNames => testNames.map(name => `regression/${name}`)
const feature = testNames => testNames.map(name => `feature/${name}`)

const CORE_TEST_ORDER = [
  ...integration([

  ]),
  ...regression([

  ]),
  ...feature([
    'timestamp-service',
  ]),
  ...e2e([
  ]),
  ...unit([

  ])
]

class TestSequencer extends BaseTestSequencer {
  /**
   * Make test files run in the sequence defined in CORE_TEST_ORDER as well as customization/test/testOrder.json
   * (e.g. login comes before dashboard test). Also filter out test files not in config, so test can easily be
   * disabled. This is useful while developing tests, so you do not have to wait for 15 tests to finish until you
   * can test the one you are currently working on.
   * @param {TestRunner.Test[]} tests
   * @returns {TestRunner.Test[]}
   */
  sort (tests) {
    const coreTestDir = path.resolve(__dirname, '../../tests')
    const customizationTestDir = path.resolve(__dirname, '../../../customization/test/tests')

    let coreTests = {}
    const customizationTests = {}
    tests.forEach(test => {
      if (test.path.startsWith(coreTestDir)) {
        const relativePath = path.relative(coreTestDir, test.path).replace('.test.js', '')
        coreTests[relativePath] = test
      } else if (test.path.startsWith(customizationTestDir)) {
        const relativePath = path.relative(customizationTestDir, test.path).replace('.test.js', '')
        customizationTests[relativePath] = test
      }
    })

    // If a customization test exists with the same name and path, as the core test, then
    // run the customization test only. This allows test to be overridden.
    coreTests = Object.entries(coreTests).reduce((result, [coreRelativePath, test]) => {
      if (Object.keys(customizationTests).some((customRelativePath) => customRelativePath === coreRelativePath)) {
        return result
      }
      return Object.assign({}, result, { [coreRelativePath]: test })
    }, {})

    return [
      ...prepareTests(coreTests, CORE_TEST_ORDER),
    ]
  }
}

function prepareTests (tests, order) {
  return Object.entries(tests)
    // Do not run tests which are not defined in the test config, so it's quick and easy to exclude them.
    .filter(([relativePath]) => order.includes(relativePath))
    .sort(([relativePathA], [relativePathB]) => {
      const indexA = order.indexOf(relativePathA)
      const indexB = order.indexOf(relativePathB)

      switch (true) {
        case indexA === indexB: return 0
        case indexA === -1: return 1
        case indexB === -1: return -1
        default: return indexA < indexB ? -1 : 1
      }
    })
    .map(([, test]) => test)
}

module.exports = TestSequencer
