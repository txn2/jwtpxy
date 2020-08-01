![jwtpxy.jpg](jwtpxy.png)

# jwtpxy: JSON Web Token Reverse Proxy


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
