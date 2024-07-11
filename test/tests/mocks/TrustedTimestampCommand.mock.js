import { vi } from 'vitest'

const mockResult = 'TST info\n' +
    'Version: 1\n' +
    'Policy OID: 1.3.6.1.4.1.12345.1.1.11\n' +
    'Hash Algorithm: sha256\n' +
    ' Message data:\n' +
    '        0000 - eb 0c 81 b5 01 05 7f 2a-23 1d 2e af e0 a2 c3 60`\n' +
    '        0010 - 12 08 67 f6 fd e6 ab 0f-50 cb 8b 90 84 0f f7 c4\n' +
    'Serial number: 0x01234XXX\n' +
    'Time stamp: May 29 07:19:13 2024 GMT\n' +
    'Accuracy: 0x01 seconds, unspecified millis, unspecified micros\n' +
    'Ordering: no\n' +
    'Nonce: unspecified\n' +
    'TSA: DirName:/C=HU/L=Budapest/O=XXXXX ./organizationIdentifier=VATHU-12345678/CN=Test xxxxx TSA xxxxx 01\n'

vi.mock('../../../src/trustedTimestamp/TrustedTimestampCommand.js', () => ({
  getTsQuery: vi.fn().mockResolvedValue(Buffer.from(mockResult)),
  getTsVerify: vi.fn().mockResolvedValue('Verification: ok'),
  getTsReply: vi.fn().mockResolvedValue(mockResult),
  generateTsReply: vi.fn().mockResolvedValue(mockResult),
  extractCertFromToken: vi.fn().mockResolvedValue('-----BEGIN CERTIFICATE-----\n' +
        'XXXXXXXXXXXXXXXXXXXXXXXXXXXX\n' +
        'XXXXXXXXXXXXXXXXXXXXXXXXXXXX\n' +
        'XXXXXXXXXXXXXXXXXXXXXXXXXXXX\n' +
        'XXXXXXXXXXXXXXXXXXXXXXXXXXXX\n' +
        '-----END CERTIFICATE-----\n'),
  checkSslPath: vi.fn().mockResolvedValue('/usr/bin/openssl')
}))
