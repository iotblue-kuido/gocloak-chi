package gocloakchi

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Nerzal/gocloak/v13"
	"github.com/go-chi/chi/v5"
	"net/http"
	"strings"

	"github.com/Nerzal/gocloak/v13/pkg/jwx"
	"github.com/golang-jwt/jwt/v4"
)

// NewDirectGrant instantiates a new Authenticator when using the Keycloak Direct Grant aka
// Resource Owner Password Credentials Flow
//
// see https://www.keycloak.org/docs/latest/securing_apps/index.html#_resource_owner_password_credentials_flow and
// https://tools.ietf.org/html/rfc6749#section-4.3 for more information about this flow
// noinspection GoUnusedExportedFunction
func NewDirectGrant(ctx context.Context, gocloak *gocloak.GoCloak, realm, clientID, clientSecret, allowedScope string, customHeaderName *string) Authenticator {
	return &DirectGrant{
		gocloak:          gocloak,
		realm:            realm,
		allowedScope:     allowedScope,
		customHeaderName: customHeaderName,
		clientID:         clientID,
		clientSecret:     clientSecret,
		ctx:              ctx,
	}
}

type DirectGrant struct {
	gocloak          *gocloak.GoCloak
	realm            string
	clientID         string
	clientSecret     string
	allowedScope     string
	customHeaderName *string
	ctx              context.Context
}

// CheckTokenCustomHeader used to verify authorization tokens
func (auth *DirectGrant) CheckTokenCustomHeader(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if auth.customHeaderName != nil {
			token = r.Header.Get(*auth.customHeaderName)
		}

		realm := auth.realm

		if realm == "" {
			value, ok := r.Context().Value(KeyRealm).(string)
			if ok {
				realm = value
			}
		}

		if token == "" {
			token = r.Header.Get("Authorization")
		}

		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(map[string]interface{}{"code": 403, "message": "Authorization header missing"})
			_, _ = w.Write(b)
			return
		}

		decodedToken, err := auth.stripBearerAndCheckToken(token, realm)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(map[string]interface{}{"code": 403, "message": "Invalid or malformed token: " + err.Error()})
			_, _ = w.Write(b)
			return
		}

		if !decodedToken.Valid {
			w.WriteHeader(http.StatusForbidden)
			b, _ := json.Marshal(map[string]interface{}{"code": 403, "message": "Invalid Token"})
			_, _ = w.Write(b)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (auth *DirectGrant) DecodeAndValidateToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if auth.customHeaderName != nil {
			token = r.Header.Get(*auth.customHeaderName)
		}

		if token == "" {
			token = r.Header.Get("Authorization")
		}

		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(map[string]interface{}{"code": 403, "message": "Authorization header missing"})
			_, _ = w.Write(b)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// CheckToken used to verify authorization tokens
func (auth *DirectGrant) CheckToken(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if auth.customHeaderName != nil {
			token = r.Header.Get(*auth.customHeaderName)
		}

		if token == "" {
			token = r.Header.Get("Authorization")
		}

		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(map[string]interface{}{"code": 403, "message": "Authorization header missing"})
			_, _ = w.Write(b)
			return
		}

		token = extractBearerToken(token)

		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(map[string]interface{}{"code": 403, "message": "Bearer Token missing"})
			_, _ = w.Write(b)
			return
		}

		result, err := auth.gocloak.RetrospectToken(auth.ctx, token, auth.clientID, auth.clientSecret, auth.realm)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(map[string]interface{}{"code": 403, "message": "Invalid or malformed token:" + err.Error()})
			_, _ = w.Write(b)
			return
		}

		if !*result.Active {
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(map[string]interface{}{"code": 403, "message": "Invalid or expired Token"})
			_, _ = w.Write(b)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (auth *DirectGrant) CheckScope(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if auth.customHeaderName != nil {
			token = r.Header.Get(*auth.customHeaderName)
		}

		if token == "" {
			token = r.Header.Get("Authorization")
		}

		if token == "" {
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(map[string]interface{}{"code": http.StatusUnauthorized, "message": "Authorization header missing"})
			_, _ = w.Write(b)
			return
		}

		token = extractBearerToken(token)
		claims := &jwx.Claims{}
		_, err := auth.gocloak.DecodeAccessTokenCustomClaims(auth.ctx, token, auth.realm, claims)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			b, _ := json.Marshal(map[string]interface{}{"code": http.StatusUnauthorized, "message": "Invalid or malformed token"})
			_, _ = w.Write(b)
			return
		}

		if !strings.Contains(claims.Scope, auth.allowedScope) {
			w.WriteHeader(http.StatusForbidden)
			b, _ := json.Marshal(map[string]interface{}{"code": http.StatusForbidden, "message": "Insufficient permissions to access the requested resource"})
			_, _ = w.Write(b)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (auth *DirectGrant) Enforcer(requestConfig *EnforcerConfig) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		fn := func(w http.ResponseWriter, r *http.Request) {
			//responseMode := ""
			token := ""

			if requestConfig.Permissions == nil || len(requestConfig.Permissions) <= 0 {
				auth.accessDenied(w, "Access Denied")
				return
			}

			if auth.customHeaderName != nil {
				token = r.Header.Get(*auth.customHeaderName)
			}

			if token == "" {
				token = r.Header.Get("Authorization")
			}

			if token == "" {
				auth.accessDenied(w, "Missing Authorization Token")
				return
			}

			token = extractBearerToken(token)

			if token == "" {
				auth.accessDenied(w, "invalid_bearer_token")
				return
			}

			result, err := auth.gocloak.RetrospectToken(auth.ctx, token, auth.clientID, auth.clientSecret, auth.realm)
			if err != nil {
				auth.accessDenied(w, err.Error())
				return
			}

			if !*result.Active {
				auth.accessDenied(w, "user_not_authenticated")
				return
			}

			defaultRequestMode := DecisionRequestMode
			if requestConfig.ResponseMode == nil {
				requestConfig.ResponseMode = &defaultRequestMode
			}
			var audience string
			if strings.HasPrefix(requestConfig.Audience, ":") {
				URIAudience := chi.URLParam(r, strings.ReplaceAll(requestConfig.Audience, ":", ""))
				audience = requestConfig.Prefix + URIAudience + requestConfig.Postfix
			} else if strings.HasPrefix(strings.ToLower(requestConfig.Audience), "x-") {
				audience = requestConfig.Prefix + r.Header.Get(requestConfig.Audience) + requestConfig.Postfix
			} else {
				audience = requestConfig.Prefix + requestConfig.Audience + requestConfig.Postfix
			}

			var strPermissions []string
			var permissionsMap []EnforcerConfigPermission
			permissionsMap = make([]EnforcerConfigPermission, len(requestConfig.Permissions))
			copy(permissionsMap, requestConfig.Permissions)
			for i, permission := range permissionsMap {
				var resource string
				if strings.HasPrefix(permission.Resource, ":") {
					resource = chi.URLParam(r, strings.ReplaceAll(permission.Resource, ":", ""))
					permissionsMap[i].Resource = resource
				} else if strings.HasPrefix(permission.Resource, "x-") {
					resource = r.Header.Get(permission.Resource)
					permissionsMap[i].Resource = r.Header.Get(permission.Resource)
				} else {
					resource = permission.Resource
				}
				strPermissions = append(strPermissions, fmt.Sprintf("%s#%s", resource, permission.Scope))
			}

			permissions, err := auth.gocloak.GetRequestingPartyPermissions(auth.ctx, token, auth.realm, gocloak.RequestingPartyTokenOptions{
				Permissions:  &strPermissions,
				Audience:     gocloak.StringP(audience),
				ResponseMode: gocloak.StringP(string(*requestConfig.ResponseMode)),
			})

			if err != nil {
				auth.permissionDenied(w, err.Error())
				return
			} else if len(*permissions) <= 0 || len(permissionsMap) != validatePermissions(permissions, permissionsMap) {
				auth.permissionDenied(w, "Not Authorized")
				return
			}

			user, _ := auth.gocloak.GetUserInfo(auth.ctx, token, auth.realm)
			r.WithContext(context.WithValue(r.Context(), userContextKey, user))

			next.ServeHTTP(w, r)
		}
		return http.HandlerFunc(fn)
	}
}

func (auth *DirectGrant) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := ""
		if auth.customHeaderName != nil {
			token = r.Header.Get(*auth.customHeaderName)
		}

		if token == "" {
			token = r.Header.Get("Authorization")
		}

		if token == "" {
			auth.accessDenied(w, "missing_authorization_token")
			return
		}

		token = extractBearerToken(token)

		if token == "" {
			auth.accessDenied(w, "invalid_bearer_token")
			return
		}

		result, err := auth.gocloak.RetrospectToken(auth.ctx, token, auth.clientID, auth.clientSecret, auth.realm)
		if err != nil {
			auth.accessDenied(w, "user_not_authenticated")
			return
		}

		if !*result.Active {
			auth.accessDenied(w, "user_not_active")
			return
		}

		user, _ := auth.gocloak.GetUserInfo(auth.ctx, token, auth.realm)
		r.WithContext(context.WithValue(r.Context(), userContextKey, user))
		next.ServeHTTP(w, r)
	})
}

func (auth *DirectGrant) accessDenied(w http.ResponseWriter, message string) {
	w.WriteHeader(http.StatusUnauthorized)
	b, _ := json.Marshal(map[string]interface{}{"code": http.StatusUnauthorized, "message": message})
	_, _ = w.Write(b)
	return
}

func (auth *DirectGrant) permissionDenied(w http.ResponseWriter, message string) {
	w.WriteHeader(http.StatusForbidden)
	b, _ := json.Marshal(map[string]interface{}{"code": http.StatusForbidden, "message": message})
	_, _ = w.Write(b)
	return
}

func (auth *DirectGrant) stripBearerAndCheckToken(accessToken string, realm string) (*jwt.Token, error) {
	accessToken = extractBearerToken(accessToken)

	decodedToken, _, err := auth.gocloak.DecodeAccessToken(auth.ctx, accessToken, realm)
	return decodedToken, err
}

func extractBearerToken(token string) string {
	return strings.Replace(token, "Bearer ", "", 1)
}

func validatePermissions(permissions *[]gocloak.RequestingPartyPermission, permissionsConfig []EnforcerConfigPermission) int {
	var totalCount int

	for _, permission := range permissionsConfig {
		if containsPermission(permissions, permission) {
			totalCount++
		}
	}
	return totalCount
}

func containsPermission(permissions *[]gocloak.RequestingPartyPermission, x EnforcerConfigPermission) bool {
	for _, n := range *permissions {
		if x.Resource == *n.ResourceName {
			return contains(*n.Scopes, x.Scope)
		}
	}
	return false
}

func contains(s []string, searchTerm string) bool {
	for i := 0; i < len(s); i++ {
		if searchTerm == s[i] {
			return true
		}
	}
	return false
}
