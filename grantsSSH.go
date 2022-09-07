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
func (s SSHGrantEndpoint) DoHTTPRequest(method string, req, resp interface{}) error {
	return s.DoHTTPRequestWithAuth(method, req, resp, "")
}

// DoHTTPRequestWithAuth performs an http request to the ssh grant endpoint
func (s SSHGrantEndpoint) DoHTTPRequestWithAuth(
	method string, req interface{}, resp interface{}, mytoken string,
) error {
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

// APIAdd is a rather high level function to add a new ssh key; this includes sending the initial request including
// the public key, starting the necessary authorization code flow. This function starts the flow with the passed
// parameters and performs the polling for the ssh username and configuration.
// The passed PollingCallbacks are called throughout the flow.
// If the used mytoken changes (due to token rotation), the new mytoken is returned in the non-nil *api.MytokenResponse
func (s SSHGrantEndpoint) APIAdd(
	mytoken, sshKey, name string, restrictions api.Restrictions, capabilities api.Capabilities,
	callbacks PollingCallbacks,
) (response api.SSHKeyAddFinalResponse, tokenUpdate *api.MytokenResponse, err error) {
	initRes, err := s.APIInitAddSSHKey(mytoken, sshKey, name, restrictions, capabilities)
	tokenUpdate = initRes.TokenUpdate
	if err != nil {
		return
	}
	if err = callbacks.Init(initRes.ConsentURI); err != nil {
		return
	}
	resp, err := s.APIPoll(initRes.PollingInfo, callbacks.Callback)
	if err != nil {
		return
	}
	callbacks.End()
	response = *resp
	return
}

// Add is a rather high level function to add a new ssh key; this includes sending the initial request including
// the public key, starting the necessary authorization code flow. This function starts the flow with the passed
// parameters and performs the polling for the ssh username and configuration.
// The passed PollingCallbacks are called throughout the flow.
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (s SSHGrantEndpoint) Add(
	mytoken *string, sshKey, name string, restrictions api.Restrictions, capabilities api.Capabilities,
	callbacks PollingCallbacks,
) (api.SSHKeyAddFinalResponse, error) {
	resp, tokenUpdate, err := s.APIAdd(*mytoken, sshKey, name, restrictions, capabilities, callbacks)
	if tokenUpdate != nil {
		*mytoken = tokenUpdate.Mytoken
	}
	return resp, err
}

// APIInitAddSSHKey starts the flow to add an ssh key; it returns the api.AuthCodeFlowResponse
func (s SSHGrantEndpoint) APIInitAddSSHKey(
	mytoken, sshKey, name string, restrictions api.Restrictions, capabilities api.Capabilities,
) (resp api.SSHKeyAddResponse, err error) {
	req := api.SSHKeyAddRequest{
		Mytoken:      mytoken,
		SSHKey:       sshKey,
		Name:         name,
		Restrictions: restrictions,
		Capabilities: capabilities,
		GrantType:    api.GrantTypeMytoken,
	}
	err = s.DoHTTPRequest("POST", req, &resp)
	return
}

// APIPoll performs the polling for the final ssh username in the add ssh key flow using the passed api.PollingInfo.
// The callback function takes the polling interval and the number of iteration as parameters; it is called for each
// polling attempt where the final mytoken could not yet be obtained (but no error occurred); it is usually used to
// print progress output.
// At the end the api.SSHKeyAddFinalResponse is returned.
func (s SSHGrantEndpoint) APIPoll(res api.PollingInfo, callback func(int64, int)) (*api.SSHKeyAddFinalResponse, error) {
	var resp api.SSHKeyAddFinalResponse
	set, err := poll(res, callback, s, &resp)
	if err != nil {
		return nil, err
	}
	if !set {
		return nil, nil
	}
	return &resp, nil
}

// APIPollOnce sends a single polling request with the passed pollingCode; it returns the api.SSHKeyAddFinalResponse
// if obtained, or an error if an error occurred.
func (s SSHGrantEndpoint) APIPollOnce(pollingCode string) (*api.SSHKeyAddFinalResponse, error) {
	var resp api.SSHKeyAddFinalResponse
	set, err := pollOnce(pollingCode, s, &resp)
	if err != nil {
		return nil, err
	}
	if !set {
		return nil, nil
	}
	return &resp, nil
}
