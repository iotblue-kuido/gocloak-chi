# gocloak-chi
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fiotblue-kuido%2Fgocloak-chi.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fiotblue-kuido%2Fgocloak-chi?ref=badge_shield)

Keycloak handler &amp; middleware for echo

This project is still WiP and the interfaces might change pretty often

Supported authentication flows:
 - Direct Grant Flow

Use this together with the keycloak client [gocloak](https://github.com/Nerzal/gocloak)

## Usage examples

* Install the package

```bash
go get "github.com/Nerzal/gocloak/v13"
```

```
// AuthenticationHandler is used to authenticate with the api
type AuthenticationHandler interface {
	AuthenticateClient(Authenticate) (*gocloak.JWT, error)
	AuthenticateUser(Authenticate) (*gocloak.JWT, error)
	RefreshToken(Refresh) (*gocloak.JWT, error)
}
```

```
// AuthenticationMiddleWare is used to validate the JWT
type AuthenticationMiddleWare interface {
	CheckToken(next echo.HandlerFunc) echo.HandlerFunc
    CheckTokenCustomHeader(next echo.HandlerFunc) echo.HandlerFunc
	CheckScope(next echo.HandlerFunc) echo.HandlerFunc
    DecodeAndValidateToken(next echo.HandlerFunc) echo.HandlerFunc
}
```

## Compatibility Matrix

This middleware uses echo and gocloak. Choose the right version for you

| Versions         | Compatibility       |
|------------------|---------------------|
| gockloak-chi/v13 | gocloak/v13, chi/v4 |

## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fiotblue-kuido%2Fgocloak-chi.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fiotblue-kuido%2Fgocloak-chi?ref=badge_large)
