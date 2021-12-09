package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// RevocationEndpoint is type representing a mytoken server's Revocation Endpoint and the actions that can be
// performed there.
type RevocationEndpoint struct {
	endpoint string
}

// DoHTTPRequest performs an http request to the revocation endpoint
func (r RevocationEndpoint) DoHTTPRequest(method string, req interface{}, resp interface{}) error {
	return doHTTPRequest(method, r.endpoint, req, resp)
}

func newRevocationEndpoint(endpoint string) *RevocationEndpoint {
	return &RevocationEndpoint{
		endpoint: endpoint,
	}
}

// Revoke revokes the passed mytoken; if recursive is true also all subtokens (and their subtokens...) are revoked.
func (r RevocationEndpoint) Revoke(mytoken string, oidcIssuer string, recursive bool) error {
	req := api.RevocationRequest{
		Token:      mytoken,
		Recursive:  recursive,
		OIDCIssuer: oidcIssuer,
	}
	return r.DoHTTPRequest("POST", req, nil)
}
