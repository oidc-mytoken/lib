package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// GetAccessToken uses the passed mytoken to return an access token with the specified attributes. If a non-empty string
// is passed as the oidcIssuer it must match the oidc issuer of the mytoken. If scopes and audiences are passed the
// access token is requested with these parameters, if omitted the default values for this mytoken / provider are used.
// Multiple scopes are passed as a space separated string. The comment details how the access token is intended to be
// used.
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (my *MytokenServer) GetAccessToken(
	mytoken *string, oidcIssuer string, scopes, audiences []string, comment string,
) (string, error) {
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
