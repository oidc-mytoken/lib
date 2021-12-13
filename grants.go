package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// GrantsEndpoint is type representing a mytoken server's grants Endpoint and the actions that can be
// performed there.
type GrantsEndpoint struct {
	endpoint string
	SSH      *SSHGrantEndpoint
}

func newGrantsEndpoint(endpoint string) *GrantsEndpoint {
	return &GrantsEndpoint{
		endpoint: endpoint,
		SSH:      newSSHGrantEndpoint(endpoint),
	}
}

// DoHTTPRequest performs an http request to the grants endpoint
func (g GrantsEndpoint) DoHTTPRequest(method string, req interface{}, resp interface{}) error {
	return doHTTPRequest(method, g.endpoint, req, resp)
}

// DoHTTPRequestWithAuth performs an http request to the grants endpoint
func (g GrantsEndpoint) DoHTTPRequestWithAuth(method string, req interface{}, resp interface{}, mytoken string) error {
	return doHTTPRequestWithAuth(method, g.endpoint, req, resp, mytoken)
}

// APIGet returns the api.GrantTypeInfoResponse about the enabled grant types for this user.
// If the used mytoken changes (due to token rotation), the new mytoken is included in the api.GrantTypeInfoResponse
func (g GrantsEndpoint) APIGet(mytoken string) (resp api.GrantTypeInfoResponse, err error) {
	err = g.DoHTTPRequestWithAuth("GET", nil, &resp, mytoken)
	return
}

// Get returns a slice of api.GrantTypeInfo about the enabled grant types for this user.
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (g GrantsEndpoint) Get(mytoken *string) ([]api.GrantTypeInfo, error) {
	resp, err := g.APIGet(*mytoken)
	if err != nil {
		return nil, err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return resp.GrantTypes, nil
}

func (g GrantsEndpoint) changeGrant(method, mytoken, grant string) (resp api.OnlyTokenUpdateResponse, err error) {
	req := api.GrantTypeRequest{
		GrantType: grant,
		Mytoken:   mytoken,
	}
	err = g.DoHTTPRequest(method, req, &resp)
	return
}

// APIEnableGrant enables the passed grant for this user.
// If the used mytoken changes (due to token rotation), the new mytoken is included in the api.OnlyTokenUpdateResponse
func (g GrantsEndpoint) APIEnableGrant(mytoken, grant string) (resp api.OnlyTokenUpdateResponse, err error) {
	return g.changeGrant("POST", mytoken, grant)
}

// EnableGrant enables the passed grant for this user.
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (g GrantsEndpoint) EnableGrant(mytoken *string, grant string) (err error) {
	res, err := g.APIEnableGrant(*mytoken, grant)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		*mytoken = res.TokenUpdate.Mytoken
	}
	return nil
}

// APIDisableGrant disables the passed grant for this user.
// If the used mytoken changes (due to token rotation), the new mytoken is included in the api.OnlyTokenUpdateResponse
func (g GrantsEndpoint) APIDisableGrant(mytoken, grant string) (resp api.OnlyTokenUpdateResponse, err error) {
	return g.changeGrant("DELETE", mytoken, grant)
}

// DisableGrant disables the passed grant for this user.
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (g GrantsEndpoint) DisableGrant(mytoken *string, grant string) (err error) {
	res, err := g.APIDisableGrant(*mytoken, grant)
	if err != nil {
		return err
	}
	if res.TokenUpdate != nil {
		*mytoken = res.TokenUpdate.Mytoken
	}
	return nil
}
