package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// TransferEndpoint is type representing a mytoken server's Token Transfer Endpoint and the actions that can be
// performed there.
type TransferEndpoint struct {
	endpoint string
}

func newTransferEndpoint(endpoint string) *TransferEndpoint {
	return &TransferEndpoint{
		endpoint: endpoint,
	}
}

// DoHTTPRequest performs an http request to the token transfer endpoint
func (t TransferEndpoint) DoHTTPRequest(method string, req, resp interface{}) error {
	return doHTTPRequest(method, t.endpoint, req, resp)
}

// APICreate creates a new transfer code for the passed mytoken and returns the api response
func (t TransferEndpoint) APICreate(mytoken string) (api.TransferCodeResponse, error) {
	req := api.CreateTransferCodeRequest{
		Mytoken: mytoken,
	}
	var resp api.TransferCodeResponse
	err := t.DoHTTPRequest("POST", req, &resp)
	return resp, err
}

// Create creates a new transfer code for the passed mytoken
func (t TransferEndpoint) Create(mytoken string) (string, error) {
	resp, err := t.APICreate(mytoken)
	return resp.TransferCode, err
}
