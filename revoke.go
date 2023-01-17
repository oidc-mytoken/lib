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
func (r RevocationEndpoint) DoHTTPRequest(method string, req, resp interface{}) error {
	return doHTTPRequest(method, r.endpoint, req, resp)
}

func newRevocationEndpoint(endpoint string) *RevocationEndpoint {
	return &RevocationEndpoint{
		endpoint: endpoint,
	}
}

// Revoke revokes the passed mytoken; if recursive is true also all subtokens (and their subtokens...) are revoked.
func (r RevocationEndpoint) Revoke(mytoken, oidcIssuer string, recursive bool) error {
	req := api.RevocationRequest{
		Token:      mytoken,
		Recursive:  recursive,
		OIDCIssuer: oidcIssuer,
	}
	return r.DoHTTPRequest("POST", req, nil)
}

// RevokeID revokes the mytoken with the passed mom id; using the passed mytoken as authorization; if
// recursive is true also all subtokens (and their subtokens...) are revoked.
func (r RevocationEndpoint) RevokeID(momID, mytoken, oidcIssuer string, recursive bool) error {
	req := api.RevocationRequest{
		MOMID:      momID,
		Token:      mytoken,
		Recursive:  recursive,
		OIDCIssuer: oidcIssuer,
	}
	return r.DoHTTPRequest("POST", req, nil)
}
