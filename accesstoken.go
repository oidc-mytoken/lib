package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

func (my *MytokenServer) GetAccessToken(mytoken *string, oidcIssuer string, scopes, audiences []string, comment string) (string, error) {
	req := NewAccessTokenRequest(oidcIssuer, *mytoken, scopes, audiences, comment)
	var resp api.AccessTokenResponse
	if err := doHTTPRequest("POST", my.AccessTokenEndpoint, req, &resp); err != nil {
		return "", err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return resp.AccessToken, nil
}
