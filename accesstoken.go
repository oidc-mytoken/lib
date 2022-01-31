package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// AccessTokenEndpoint is type representing a mytoken server's Access Token Endpoint and the actions that can be
// performed there.
type AccessTokenEndpoint struct {
	endpoint string
}

func newAccessTokenEndpoint(endpoint string) *AccessTokenEndpoint {
	return &AccessTokenEndpoint{
		endpoint: endpoint,
	}
}

// DoHTTPRequest performs an http request to the access token endpoint
func (at AccessTokenEndpoint) DoHTTPRequest(method string, req, resp interface{}) error {
	return doHTTPRequest(method, at.endpoint, req, resp)
}

// APIGet uses the passed mytoken to return an access token with the specified attributes. If a non-empty string
// is passed as the oidcIssuer it must match the oidc issuer of the mytoken. If scopes and audiences are passed the
// access token is requested with these parameters, if omitted the default values for this mytoken / provider are used.
// Multiple scopes are passed as a space separated string. The comment details how the access token is intended to be
// used.
// If the used mytoken changes (due to token rotation), the new mytoken is included in the api.AccessTokenResponse
func (at AccessTokenEndpoint) APIGet(
	mytoken string, oidcIssuer string, scopes, audiences []string, comment string,
) (resp api.AccessTokenResponse, err error) {
	req := NewAccessTokenRequest(oidcIssuer, mytoken, scopes, audiences, comment)
	err = at.DoHTTPRequest("POST", req, &resp)
	return
}

// Get uses the passed mytoken to return an access token with the specified attributes. If a non-empty string
// is passed as the oidcIssuer it must match the oidc issuer of the mytoken. If scopes and audiences are passed the
// access token is requested with these parameters, if omitted the default values for this mytoken / provider are used.
// Multiple scopes are passed as a space separated string. The comment details how the access token is intended to be
// used.
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (at AccessTokenEndpoint) Get(
	mytoken *string, oidcIssuer string, scopes, audiences []string, comment string,
) (string, error) {
	resp, err := at.APIGet(*mytoken, oidcIssuer, scopes, audiences, comment)
	if err != nil {
		return "", err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return resp.AccessToken, nil
}
