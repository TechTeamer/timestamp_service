# Proxy configuration

## Configure local proxy

```shell
cd proxy
docker-compose up
```

## Application usage

```json
{
  "trustedTimestamp": {
    "certsLocation": "/etc/ssl/certs/",
    "providers": [
      {
        "name": "bteszt",
        "url": "https://bteszt.e-szigno.hu/tsa",
        "auth": {
          "user": "<username>",
          "pass": "<password>"
        },
        "proxy": {
          "url": "http://localhost:8080",
          "allowUnauthorized": true
        }
      }
    ]
  }
}
```
