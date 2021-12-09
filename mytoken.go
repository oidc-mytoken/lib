package mytokenlib

import (
	"errors"
	"fmt"
	"time"

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

// FromRequest sends the passed request marshalled as json to the servers mytoken endpoint to obtain a mytoken and
// returns the obtained mytoken and if a mytoken was used for authorization and it was rotated the updated mytoken.
func (my MytokenEndpoint) FromRequest(request interface{}) (string, *string, error) {
	var resp api.MytokenResponse
	if err := my.DoHTTPRequest("POST", request, &resp); err != nil {
		return "", nil, err
	}
	var updatedMT *string
	if resp.TokenUpdate != nil {
		updatedMT = &resp.TokenUpdate.Mytoken
	}
	return resp.Mytoken, updatedMT, nil
}

// FromMytoken obtains a sub-mytoken by using an existing mytoken according to the passed parameters.
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (my MytokenEndpoint) FromMytoken(
	mytoken *string, issuer string, restrictions api.Restrictions, capabilities, subtokenCapabilities api.Capabilities,
	responseType, name string,
) (string, error) {
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
		Mytoken: *mytoken,
	}
	mt, mtUpdate, err := my.FromRequest(req)
	if mtUpdate != nil {
		*mytoken = *mtUpdate
	}
	return mt, err
}

// FromTransferCode exchanges the transferCode into the linked mytoken
func (my MytokenEndpoint) FromTransferCode(transferCode string) (string, error) {
	req := api.ExchangeTransferCodeRequest{
		GrantType:    api.GrantTypeTransferCode,
		TransferCode: transferCode,
	}
	mt, _, err := my.FromRequest(req)
	return mt, err
}

// PollingCallbacks is a struct holding callback related to the polling in the authorization code flow.
// The Init function takes the authorization url and is called before the starting polling the server; this callback
// usually displays information to the user how to proceed, including the passed authorization url
// The Callback function takes the polling interval and the number of iteration as parameters; it is called for each
// polling attempt where the final mytoken could not yet be obtained (but no error occurred); it is usually used to
// print progress output.
// The End function is called after the mytoken was successfully obtained and might be used to finish output printed
// to the user.
type PollingCallbacks struct {
	Init     func(string) error
	Callback func(int64, int)
	End      func()
}

// FromAuthorizationFlow is a rather high level function that obtains a new mytoken using the authorization
// code flow. This function starts the flow with the passed parameters and performs the polling for the mytoken.
// The passed PollingCallbacks are called throughout the flow.
func (my MytokenEndpoint) FromAuthorizationFlow(
	issuer string, restrictions api.Restrictions, capabilities, subtokenCapabilities api.Capabilities,
	responseType, name string, callbacks PollingCallbacks,
) (string, error) {
	authRes, err := my.InitAuthorizationFlow(
		issuer, restrictions, capabilities, subtokenCapabilities, responseType, name,
	)
	if err != nil {
		return "", err
	}
	if err = callbacks.Init(authRes.AuthorizationURL); err != nil {
		return "", err
	}
	tok, err := my.Poll(authRes.PollingInfo, callbacks.Callback)
	if err == nil {
		callbacks.End()
	}
	return tok, err
}

// InitAuthorizationFlow starts the authorization code flow to obtain a mytoken with the passed parameters; it
// returns the api.AuthCodeFlowResponse
func (my MytokenEndpoint) InitAuthorizationFlow(
	issuer string, restrictions api.Restrictions, capabilities, subtokenCapabilities api.Capabilities,
	responseType, name string,
) (*api.AuthCodeFlowResponse, error) {
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
	var resp api.AuthCodeFlowResponse
	if err := my.DoHTTPRequest("POST", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// Poll performs the polling for the final mytoken in the authorization code flow using the passed api.
// PollingInfo.
// The callback function takes the polling interval and the number of iteration as parameters; it is called for each
// polling attempt where the final mytoken could not yet be obtained (but no error occurred); it is usually used to
// print progress output.
// At the end the mytoken is returned.
func (my MytokenEndpoint) Poll(res api.PollingInfo, callback func(int64, int)) (string, error) {
	expires := time.Now().Add(time.Duration(res.PollingCodeExpiresIn) * time.Second)
	interval := res.PollingInterval
	if interval == 0 {
		interval = 5
	}
	tick := time.NewTicker(time.Duration(interval) * time.Second)
	defer tick.Stop()
	i := 0
	for t := range tick.C {
		if t.After(expires) {
			break
		}
		tok, set, err := my.PollOnce(res.PollingCode)
		if err != nil {
			return "", err
		}
		if set {
			return tok, nil
		}
		callback(res.PollingInterval, i)
		i++
	}
	return "", fmt.Errorf("polling code expired")
}

// PollOnce sends a single polling request with the passed pollingCode; it returns the mytoken if obtained,
// a bool indicating if the mytoken was obtained, or an error if an error occurred.
func (my MytokenEndpoint) PollOnce(pollingCode string) (string, bool, error) {
	req := api.PollingCodeRequest{
		GrantType:   api.GrantTypePollingCode,
		PollingCode: pollingCode,
	}

	tok, _, err := my.FromRequest(req)
	if err == nil {
		return tok, true, nil
	}
	var myErr *MytokenError
	if errors.As(err, &myErr) {
		if myErr.err == api.ErrorStrAuthorizationPending {
			err = nil
		}
	}
	return tok, false, err
}
