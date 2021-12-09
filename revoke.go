package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// Revoke revokes the passed mytoken; if recursive is true also all subtokens (and their subtokens...) are revoked.
func (my *MytokenServer) Revoke(mytoken string, oidcIssuer string, recursive bool) error {
	req := api.RevocationRequest{
		Token:      mytoken,
		Recursive:  recursive,
		OIDCIssuer: oidcIssuer,
	}
	return doHTTPRequest("POST", my.RevocationEndpoint, req, nil)
}
