package provider

import "strings"

// Config holds OIDC endpoint paths and scopes for a provider.
type Config struct {
	Name              string
	AuthorizeEndpoint string
	TokenEndpoint     string
	Scopes            string
	ResponseType      string
	ResponseMode      string
}

// Configs maps provider type to its OIDC configuration.
//
// For Okta, the endpoints template in /oauth2/default/... points at the
// pre-provisioned "default" Custom Authorization Server that every Okta
// Developer / Integrator tenant ships with, and that every Workforce
// Identity tenant has out of the box. Customers whose admin renamed the
// CAS set okta_auth_server_id in their ccwb profile and ConfigFor() rewrites
// the paths at runtime. Only a Custom AS can host admin-defined claims like
// https://aws.amazon.com/tags/principal_tags/Project -- the Org AS cannot,
// which is why we never point at it.
var Configs = map[string]Config{
	"okta": {
		Name:              "Okta",
		AuthorizeEndpoint: "/oauth2/default/v1/authorize",
		TokenEndpoint:     "/oauth2/default/v1/token",
		Scopes:            "openid profile email",
		ResponseType:      "code",
		ResponseMode:      "query",
	},
	"auth0": {
		Name:              "Auth0",
		AuthorizeEndpoint: "/authorize",
		TokenEndpoint:     "/oauth/token",
		Scopes:            "openid profile email",
		ResponseType:      "code",
		ResponseMode:      "query",
	},
	"azure": {
		Name:              "Azure AD",
		AuthorizeEndpoint: "/oauth2/v2.0/authorize",
		TokenEndpoint:     "/oauth2/v2.0/token",
		Scopes:            "openid profile email",
		ResponseType:      "code",
		ResponseMode:      "query",
	},
	"cognito": {
		Name:              "AWS Cognito User Pool",
		AuthorizeEndpoint: "/oauth2/authorize",
		TokenEndpoint:     "/oauth2/token",
		Scopes:            "openid email",
		ResponseType:      "code",
		ResponseMode:      "query",
	},
}

// ConfigFor returns the OIDC configuration for a provider, applying per-
// profile customizations. Today the only customization is the Okta Custom
// Authorization Server id: a non-empty value other than "default" rewrites
// /oauth2/default/... to /oauth2/<id>/... for both the authorize and token
// endpoints. Callers pass oktaAuthServerID unconditionally (from
// config.json); non-Okta providers ignore it. Returns a zero-value Config
// when providerType is unknown.
func ConfigFor(providerType, oktaAuthServerID string) Config {
	cfg, ok := Configs[providerType]
	if !ok {
		return Config{}
	}
	if providerType != "okta" {
		return cfg
	}
	id := strings.TrimSpace(oktaAuthServerID)
	if id == "" || id == "default" {
		return cfg
	}
	const oldSeg = "/oauth2/default/"
	newSeg := "/oauth2/" + id + "/"
	cfg.AuthorizeEndpoint = strings.Replace(cfg.AuthorizeEndpoint, oldSeg, newSeg, 1)
	cfg.TokenEndpoint = strings.Replace(cfg.TokenEndpoint, oldSeg, newSeg, 1)
	return cfg
}

// IsKnown returns true if providerType is a recognized provider.
func IsKnown(providerType string) bool {
	_, ok := Configs[providerType]
	return ok
}
