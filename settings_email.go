package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// EmailSettingsEndpoint is type representing a mytoken server's Email Settings Endpoint
type EmailSettingsEndpoint struct {
	endpoint string
}

func newEmailSettingsEndpoint(endpoint string) *EmailSettingsEndpoint {
	return &EmailSettingsEndpoint{endpoint: endpoint}
}

// APIGet retrieves the user's email settings information
func (e EmailSettingsEndpoint) APIGet(mytoken string) (resp api.MailSettingsInfoResponse, err error) {
	err = e.DoHTTPRequestWithAuth("GET", nil, &resp, mytoken)
	return
}

// APIUpdate updates the user's email settings
func (e EmailSettingsEndpoint) APIUpdate(mytoken, emailAddress string, preferHTMLMail *bool) (resp api.OnlyTokenUpdateResponse, err error) {
	req := api.UpdateMailSettingsRequest{}
	if emailAddress != "" {
		req.EmailAddress = emailAddress
	}
	if preferHTMLMail != nil {
		req.PreferHTMLMail = preferHTMLMail
	}
	err = e.DoHTTPRequestWithAuth("PUT", req, &resp, mytoken)
	return
}

// DoHTTPRequest performs an http request to the email settings endpoint
func (e EmailSettingsEndpoint) DoHTTPRequest(method string, req, resp interface{}) error {
	return doHTTPRequest(method, e.endpoint, req, resp)
}

// DoHTTPRequestWithAuth performs an http request to the email settings endpoint with mytoken authorization
func (e EmailSettingsEndpoint) DoHTTPRequestWithAuth(method string, req, resp interface{}, mytoken string) error {
	return doHTTPRequestWithAuth(method, e.endpoint, req, resp, mytoken)
}
