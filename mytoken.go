package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// MytokenEndpoint is type representing a mytoken server's Mytoken Endpoint and the actions that can be
// performed there.
type MytokenEndpoint struct {
	endpoint string
}

func newMytokenEndpoint(endpoint string) *MytokenEndpoint {
	return &MytokenEndpoint{
		endpoint: endpoint,
	}
}

// DoHTTPRequest performs an http request to the mytoken endpoint
func (my MytokenEndpoint) DoHTTPRequest(method string, req interface{}, resp interface{}) error {
	return doHTTPRequest(method, my.endpoint, req, resp)
}

// APIFromRequest sends the passed request marshalled as json to the servers mytoken endpoint to obtain a mytoken and
// returns the api.MytokenResponse.
func (my MytokenEndpoint) APIFromRequest(request interface{}) (resp api.MytokenResponse, err error) {
	err = my.DoHTTPRequest("POST", request, &resp)
	return
}

// FromRequest sends the passed request marshalled as json to the servers mytoken endpoint to obtain a mytoken and
// returns the obtained mytoken and if a mytoken was used for authorization and it was rotated the updated mytoken.
func (my MytokenEndpoint) FromRequest(request interface{}) (string, *string, error) {
	resp, err := my.APIFromRequest(request)
	if err != nil {
		return "", nil, err
	}
	var updatedMT *string
	if resp.TokenUpdate != nil {
		updatedMT = &resp.TokenUpdate.Mytoken
	}
	return resp.Mytoken, updatedMT, nil
}

// APIFromMytoken obtains a sub-mytoken by using an existing mytoken according to the passed parameters.
// If the used mytoken changes (due to token rotation), the new mytoken is included in the api.MytokenResponse
func (my MytokenEndpoint) APIFromMytoken(
	mytoken string, issuer string, restrictions api.Restrictions, capabilities, subtokenCapabilities api.Capabilities,
	responseType, name string,
) (api.MytokenResponse, error) {
	req := api.MytokenFromMytokenRequest{
		GeneralMytokenRequest: api.GeneralMytokenRequest{
			Issuer:               issuer,
			GrantType:            api.GrantTypeMytoken,
			Restrictions:         restrictions,
			Capabilities:         capabilities,
			SubtokenCapabilities: subtokenCapabilities,
			Name:                 name,
			ResponseType:         responseType,
		},
		Mytoken: mytoken,
	}
	return my.APIFromRequest(req)
}

// FromMytoken obtains a sub-mytoken by using an existing mytoken according to the passed parameters.
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (my MytokenEndpoint) FromMytoken(
	mytoken *string, issuer string, restrictions api.Restrictions, capabilities, subtokenCapabilities api.Capabilities,
	responseType, name string,
) (string, error) {
	resp, err := my.APIFromMytoken(*mytoken, issuer, restrictions, capabilities, subtokenCapabilities, responseType, name)
	if err != nil {
		return "", err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return resp.Mytoken, nil
}

// APIFromTransferCode exchanges the transferCode into the linked mytoken
func (my MytokenEndpoint) APIFromTransferCode(transferCode string) (api.MytokenResponse, error) {
	req := api.ExchangeTransferCodeRequest{
		GrantType:    api.GrantTypeTransferCode,
		TransferCode: transferCode,
	}
	return my.APIFromRequest(req)
}

// FromTransferCode exchanges the transferCode into the linked mytoken
func (my MytokenEndpoint) FromTransferCode(transferCode string) (string, error) {
	resp, err := my.APIFromTransferCode(transferCode)
	return resp.Mytoken, err
}

// APIFromAuthorizationFlow is a rather high level function that obtains a new mytoken using the authorization
// code flow. This function starts the flow with the passed parameters and performs the polling for the mytoken.
// The passed PollingCallbacks are called throughout the flow.
func (my MytokenEndpoint) APIFromAuthorizationFlow(
	issuer string, restrictions api.Restrictions, capabilities, subtokenCapabilities api.Capabilities,
	responseType, name string, callbacks PollingCallbacks,
) (api.MytokenResponse, error) {
	authRes, err := my.APIInitAuthorizationFlow(
		issuer, restrictions, capabilities, subtokenCapabilities, responseType, name,
	)
	if err != nil {
		return api.MytokenResponse{}, err
	}
	if err = callbacks.Init(authRes.AuthorizationURL); err != nil {
		return api.MytokenResponse{}, err
	}
	resp, err := my.APIPoll(authRes.PollingInfo, callbacks.Callback)
	if err != nil {
		return api.MytokenResponse{}, err
	}
	callbacks.End()
	return *resp, nil
}

// FromAuthorizationFlow is a rather high level function that obtains a new mytoken using the authorization
// code flow. This function starts the flow with the passed parameters and performs the polling for the mytoken.
// The passed PollingCallbacks are called throughout the flow.
func (my MytokenEndpoint) FromAuthorizationFlow(
	issuer string, restrictions api.Restrictions, capabilities, subtokenCapabilities api.Capabilities,
	responseType, name string, callbacks PollingCallbacks,
) (string, error) {
	resp, err := my.APIFromAuthorizationFlow(issuer, restrictions, capabilities, subtokenCapabilities, responseType, name, callbacks)
	return resp.Mytoken, err
}

// APIInitAuthorizationFlow starts the authorization code flow to obtain a mytoken with the passed parameters; it
// returns the api.AuthCodeFlowResponse
func (my MytokenEndpoint) APIInitAuthorizationFlow(
	issuer string, restrictions api.Restrictions, capabilities, subtokenCapabilities api.Capabilities,
	responseType, name string,
) (resp api.AuthCodeFlowResponse, err error) {
	req := api.AuthCodeFlowRequest{
		OIDCFlowRequest: api.OIDCFlowRequest{
			GeneralMytokenRequest: api.GeneralMytokenRequest{
				Issuer:               issuer,
				GrantType:            api.GrantTypeOIDCFlow,
				Restrictions:         restrictions,
				Capabilities:         capabilities,
				SubtokenCapabilities: subtokenCapabilities,
				Name:                 name,
				ResponseType:         responseType,
			},
			OIDCFlow: api.OIDCFlowAuthorizationCode,
		},
		RedirectType: "native",
	}
	err = my.DoHTTPRequest("POST", req, &resp)
	return
}

// APIPoll performs the polling for the final mytoken in the authorization code flow using the passed
// api.PollingInfo.
// The callback function takes the polling interval and the number of iteration as parameters; it is called for each
// polling attempt where the final mytoken could not yet be obtained (but no error occurred); it is usually used to
// print progress output.
// At the end the api.MytokenResponse is returned.
func (my MytokenEndpoint) APIPoll(res api.PollingInfo, callback func(int64, int)) (*api.MytokenResponse, error) {
	var resp api.MytokenResponse
	set, err := poll(res, callback, my, &resp)
	if err != nil {
		return nil, err
	}
	if !set {
		return nil, nil
	}
	return &resp, nil
}

// Poll performs the polling for the final mytoken in the authorization code flow using the passed
// api.PollingInfo.
// The callback function takes the polling interval and the number of iteration as parameters; it is called for each
// polling attempt where the final mytoken could not yet be obtained (but no error occurred); it is usually used to
// print progress output.
// At the end the mytoken is returned.
func (my MytokenEndpoint) Poll(res api.PollingInfo, callback func(int64, int)) (string, error) {
	resp, err := my.APIPoll(res, callback)
	if err != nil {
		return "", err
	}
	return resp.Mytoken, nil
}

// APIPollOnce sends a single polling request with the passed pollingCode; it returns the api.
// MytokenResponse if obtained, or an error if an error occurred.
func (my MytokenEndpoint) APIPollOnce(pollingCode string) (*api.MytokenResponse, error) {
	var resp api.MytokenResponse
	set, err := pollOnce(pollingCode, my, &resp)
	if err != nil {
		return nil, err
	}
	if !set {
		return nil, nil
	}
	return &resp, nil
}

// PollOnce sends a single polling request with the passed pollingCode; it returns the mytoken if obtained,
// a bool indicating if the mytoken was obtained, or an error if an error occurred.
func (my MytokenEndpoint) PollOnce(pollingCode string) (string, bool, error) {
	resp, err := my.APIPollOnce(pollingCode)
	if err != nil {
		return "", false, err
	}
	if resp == nil {
		return "", false, nil
	}
	return resp.Mytoken, true, nil
}
