package mytokenlib

import (
	"strings"

	"github.com/oidc-mytoken/api/v0"
)

// NewAccessTokenRequest creates a new api.AccessTokenRequest with the passed arguments
func NewAccessTokenRequest(issuer, mytoken string, scopes, audiences []string, comment string) api.AccessTokenRequest {
	return api.AccessTokenRequest{
		Issuer:    issuer,
		GrantType: api.GrantTypeMytoken,
		Scope:     strings.Join(scopes, " "),
		Audience:  strings.Join(audiences, " "),
		Comment:   comment,
		Mytoken:   mytoken,
	}
}
