Timestamp
=============

Trustedtimestamp service implements the generate, import and verification of timestamps.

* [Install](#install)
* [Usage](#usage)
  * [Params](#params) 
* [Default config](#default-config)
* [Config provider options](#config-provider-options)
  * [Required fields](#required-fields)
  * [Optional fields](#optional-fields)
* [Config example](#config-example)
* [Public methods](#public-methods)


## Install


```
$ yarn add @techteamer/timestamp
```

### Usage

```
const { TrustedTimestampService: TrustedTimestampServiceLib } = require('@techteamer/timestamp')
...
this.trustedTimestampService = new TrustedTimestampServiceLib('normal', config.get('trustedTimestamp'), config.get('certService.encoding', 'latin1'))
```

#### Params
1. TimestampInfo output type format: normal, short
2. config: prodiders and cert location, config.get('trustedTimestamp')
3. encode type(optional): config.get('certService.encoding', 'latin1')

### Default config

```
  "trustedTimestamp": {
    "certsLocation": "/etc/ssl/certs/",
    "providers": [
      {
        "name": "bteszt",
        "url": "https://bteszt.e-szigno.hu/tsa",
        "auth": {
          "user": "<username>",
          "pass": "<password>"
        }
      }
    ]
  }
```

### Config provider options

#### Required fields
* name (string)
* url (string | object): Simple url string or object {getTokenUrl: string, getTimestampUrl: string}

#### Optional fields
* auth (object): Username and password for auth (object): {user: string, pass: string}
* priority (number) - The order of the service providers can be changed, the higher number is the first
* body (object) -  The infocert type provider can set body parameter
---------------------------------

### Config example
```
  "trustedTimestamp": {
    {
      "certsLocation": "/etc/ssl/certs/",
      "providers": [
        {
          "name": "bteszt",
          "url": "https://bteszt.e-szigno.hu/tsa",
          "auth": {
            "user": "<username>",
            "pass": "<password>"
          }
        },
        {
          "name": "infocert 1 test",
          "priority": 999,
          "url": {
            "getTokenUrl": "https://idpstage.infocert.digital/auth/realms/delivery/protocol/openid-connect/token",
            "getTimestampUrl": "https://apistage.infocert.digital/timestamp/v1/apply"
          },
          "auth": {
            "user": "<username>",
            "pass": "<password>"
          },
          "body": {
            "grant_type": "client_credentials",
            "scope": "timestamp"
          }
        }
      ]
    }
  }
```

### Public methods


- `getTimestampInfo`
- `createTimestampToken`
- `importTimestampToken`
- `verifyToken`
- `verifyTsr`
- `testService`
