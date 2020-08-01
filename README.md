![jwtpxy.jpg](jwtpxy.png)

# JSON Web Token Reverse Proxy

## Environment Variable Configuration

| Variable       | Default                                           | Description                   |
|:---------------|:--------------------------------------------------|:------------------------------|
| IP             | 127.0.0.1                                         | Server IP address to bind to. |
| PORT           | 8080                                              | Server port.                  |
| UTIL_PORT      | 8000                                              | Utility server port.          |
| METRICS_PORT   | 2112                                              | Metrics port.                 |
| READ_TIMEOUT   | 10                                                | HTTP read timeout             |
| WRITE_TIMEOUT  | 10                                                | HTTP write timeout            |
| DEBUG          | false                                             | Debug log level                              |
| KEYCLOAK       | http://localhost:8090/auth/realms/master          | Keycloak realm info           |
| BACKEND        | http://localhost:8000                             | Backend service                              |
| HEADER_MAPPING | From:preferred_username,Realm-Access:realm_access | Mapping HTTPS headers to token attributes.                              |
| REQUIRE_TOKEN  | true                                              | set to string "false" to allow un-authenticated pass-through.                              |
| SIG_HEADER     | shared_secret_change_me                           | Signature header / shared secret                              |
## Development

### Test

Start Keycloak
```shell script
docker-compose up -d
```

Test Call
```shell script
# install jq if you don't have it
brew install jq

# start jwtpxy
go run ./cmd/jwtpxy.go 

# retrieve an access token
export TOKEN=$(curl -X POST "http://localhost:8090/auth/realms/master/protocol/openid-connect/token" \
 -H "Content-Type: application/x-www-form-urlencoded" \
 -d "username=sysop" \
 -d "password=password" \
 -d 'grant_type=password' \
 -d 'client_id=admin-cli' | jq -r '.access_token')
 
# call the jwtpxy with the default utility backend
curl -L -X GET 'http://localhost:8080/' -H "Authorization: Bearer ${TOKEN}"
```

Cleanup
```shell script
docker-compose stop && docker-compose rm
```

### Test Release

```bash
goreleaser --skip-publish --rm-dist --skip-validate
```

### Release

```bash
GITHUB_TOKEN=$GITHUB_TOKEN goreleaser --rm-dist
```
