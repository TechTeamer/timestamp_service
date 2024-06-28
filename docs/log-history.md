# Timestamp providers log history

The library can use multiple timestamp providers when generating a timestamp. If the first provider fails, try the next one to generate the token. The process steps are stored historically.

The createtimestamp function also returns a logHistory array.

---

Usage implementation example:

```
const { timestamp, providerName, logHistory } = await this.trustedTimestampService.createTimestampToken(digest, hashAlgorithm, dataSize)
console.log(logHistory)
```

First provider success log history example:

```
{
  info: {
    name: 'btest',
    date: 2024-06-27T11:02:59.435Z,
    url: 'https://bteszt.e-szigno.hu/tsa',
    response: '200, OK',
    error: null
  },
  errorTrace: null
}
```

First provider failed, second provider success, log history example:

```
  {
    info: {
      name: 'btest2',
      date: 2024-06-27T10:52:19.695Z,
      url: 'https://bteszt.e-szigno.hu/tsa',
      reponse: null,
      error: 'TSA response unsatisfactory: 401 Unauthorized'
    },
    errorTrace: Error: TSA response unsatisfactory: 401 Unauthorized
        at ../node_modules/@techteamer/timestamp/src/trustedTimestamp/TrustedTimestampRequest.js:138:15
        at process.processTicksAndRejections (node:internal/process/task_queues:95:5)
        at async TrustedTimestampRequest._getTimeStampToken (../node_modules/@techteamer/timestamp/src/trustedTimestamp/TrustedTimestampRequest.js:136:12)
        at async TrustedTimestampRequest.getTimestamp (../node_modules/@techteamer/timestamp/src/trustedTimestamp/TrustedTimestampRequest.js:64:41)
        at async TrustedTimestampService.createTimestampToken (../node_modules/@techteamer/timestamp/src/trustedTimestamp/TrustedTimestampService.js:167:49)
        at async TrustedTimestampService.createTimestampToken (../server/service/TrustedTimestampService.js:61:55)
  },
  {
    info: {
      name: 'btest',
      date: 2024-06-27T10:52:19.721Z,
      url: 'https://bteszt.e-szigno.hu/tsa',
      response: '200, OK',
      error: null
    },
    errorTrace: null
  }
```
