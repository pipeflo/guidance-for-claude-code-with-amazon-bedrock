package provider

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
var Configs = map[string]Config{
	"okta": {
		Name: "Okta",
		// Use the "default" Custom Authorization Server rather than the Org
		// Authorization Server. Only a Custom AS lets admins configure custom
		// claims (e.g. https://aws.amazon.com/tags/principal_tags/Project),
		// which are required for per-project cost attribution. Every Okta
		// Developer / Integrator tenant has a pre-provisioned "default" CAS;
		// Workforce Identity tenants ship one out of the box. Customers using
		// a non-"default" CAS can work around this by pre-editing the
		// generated config.json (future: profile field for the CAS id).
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

// IsKnown returns true if providerType is a recognized provider.
func IsKnown(providerType string) bool {
	_, ok := Configs[providerType]
	return ok
}
