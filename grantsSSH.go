package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// SSHGrantEndpoint is type representing a mytoken server's ssh grant Endpoint and the actions that can be
// performed there.
type SSHGrantEndpoint struct {
	endpoint string
}

func newSSHGrantEndpoint(grantsEndpoint string) *SSHGrantEndpoint {
	endpoint := grantsEndpoint
	if endpoint[len(endpoint)-1] != '/' {
		endpoint += "/"
	}
	endpoint += "ssh"
	return &SSHGrantEndpoint{
		endpoint: endpoint,
	}
}

// DoHTTPRequest performs an http request to the ssh grant endpoint
func (s SSHGrantEndpoint) DoHTTPRequest(method string, req interface{}, resp interface{}) error {
	return s.DoHTTPRequestWithAuth(method, req, resp, "")
}

// DoHTTPRequestWithAuth performs an http request to the ssh grant endpoint
func (s SSHGrantEndpoint) DoHTTPRequestWithAuth(method string, req interface{}, resp interface{}, mytoken string) error {
	return doHTTPRequestWithAuth(method, s.endpoint, req, resp, mytoken)
}

// APIGet returns the api.SSHInfoResponse for this user.
// If the used mytoken changes (due to token rotation), the new mytoken is included in the api.SSHInfoResponse
func (s SSHGrantEndpoint) APIGet(mytoken string) (resp api.SSHInfoResponse, err error) {
	err = s.DoHTTPRequestWithAuth("GET", nil, &resp, mytoken)
	return
}

// Get returns a slice of api.SSHKeyInfo about the enabled ssh keys for this user and a bool indicating if the ssh
// grant is enabled or not.
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (s SSHGrantEndpoint) Get(mytoken *string) ([]api.SSHKeyInfo, bool, error) {
	resp, err := s.APIGet(*mytoken)
	if err != nil {
		return nil, false, err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return resp.SSHKeyInfo, resp.GrantEnabled, nil
}

// APIRemove removes an ssh public key, therefore disabling it. One of keyFP and publicKey must be given,
// i.e. the ssh key can be deleted by giving only the SHA256 fingerprint or the full public key.
// If the used mytoken changes (due to token rotation), the new mytoken is included in the api.OnlyTokenUpdateResponse
func (s SSHGrantEndpoint) APIRemove(mytoken, keyFP, publicKey string) (resp api.OnlyTokenUpdateResponse, err error) {
	req := api.SSHKeyDeleteRequest{
		Mytoken:           mytoken,
		SSHKey:            publicKey,
		SSHKeyFingerprint: keyFP,
	}
	err = s.DoHTTPRequest("DELETE", req, &resp)
	return
}

// Remove removes an ssh public key, therefore disabling it. One of keyFP and publicKey must be given,
// i.e. the ssh key can be deleted by giving only the SHA256 fingerprint or the full public key.
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (s SSHGrantEndpoint) Remove(mytoken *string, keyFP, publicKey string) error {
	resp, err := s.APIRemove(*mytoken, keyFP, publicKey)
	if err != nil {
		return err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return nil
}
