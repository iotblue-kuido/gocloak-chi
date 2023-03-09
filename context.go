package gocloakchi

import (
	"context"
	"fmt"
	"github.com/Nerzal/gocloak/v13"
	"net/http"
)

type contextKey string

const (
	userContextKey contextKey = "user"
	//permissionContextKey contextKey = "permission"
)

func (a *DirectGrant) setUserContext(r *http.Request, user *gocloak.UserInfo) *http.Request {
	r = r.WithContext(context.WithValue(r.Context(), userContextKey, user))
	return r
}

func UserContext(ctx context.Context, user *gocloak.UserInfo) context.Context {
	ctx = context.WithValue(ctx, userContextKey, user)
	return ctx
}

func UserFromContext(ctx context.Context) (*gocloak.UserInfo, bool) {
	u, ok := ctx.Value(userContextKey).(*gocloak.UserInfo)
	if !ok {
		return nil, false
	}
	return u, ok
}

func getString(m map[string]any, key string) (string, error) {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s, nil
		}

		return "", fmt.Errorf("mapping of %s failed, wrong type (%T)", key, v)
	}

	return "", fmt.Errorf("mapping of %s failed, missing value", key)
}

func getStringArray(m map[string]any, key string) ([]string, error) {
	if v, ok := m[key]; ok {
		if s, ok := v.([]string); ok {
			return s, nil
		}

		return nil, fmt.Errorf("mapping of %s failed, wrong type (%T)", key, v)
	}

	return nil, fmt.Errorf("mapping of %s failed, missing value", key)
}
