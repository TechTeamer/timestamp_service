const BasicProvider = require('../src/providers/BasicTimeStampProvider')
const TimestampService = require('../src/TimestampService')
const crypto = require('crypto')

const timestampService = new TimestampService({ tsaCertDir: '', algorithm: 'sha256', tempDir: './temp' })
timestampService.addProvider(new BasicProvider({
  basicAuth: '',
  url: ''
}))

async function testWithDigest () {

}
async function testWithBuffer() {

}
