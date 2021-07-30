package mytokenlib

import (
	"errors"
	"fmt"
	"time"

	"github.com/oidc-mytoken/api/v0"
	"github.com/oidc-mytoken/server/shared/httpClient"
)

func (my *MytokenProvider) GetMytoken(req interface{}) (string, error) {
	resp, err := httpClient.Do().R().SetBody(req).SetResult(&api.MytokenResponse{}).SetError(&api.Error{}).Post(my.MytokenEndpoint)
	if err != nil {
		return "", newMytokenErrorFromError("error while sending http request", err)
	}
	if e := resp.Error(); e != nil {
		if errRes := e.(*api.Error); errRes != nil && errRes.Error != "" {
			return "", &MytokenError{
				err:          errRes.Error,
				errorDetails: errRes.ErrorDescription,
			}
		}
	}
	stRes, ok := resp.Result().(*api.MytokenResponse)
	if !ok {
		return "", &MytokenError{
			err: "unexpected response from mytoken server",
		}
	}
	return stRes.Mytoken, nil
}

func (my *MytokenProvider) GetMytokenByMytoken(mytoken, issuer string, restrictions api.Restrictions, capabilities, subtokenCapabilities api.Capabilities, responseType, name string) (string, error) {
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
		Mytoken:              mytoken,
	}
	return my.GetMytoken(req)
}

func (my *MytokenProvider) GetMytokenByTransferCode(transferCode string) (string, error) {
	req := api.ExchangeTransferCodeRequest{
		GrantType:    api.GrantTypeTransferCode,
		TransferCode: transferCode,
	}
	return my.GetMytoken(req)
}

type PollingCallbacks struct {
	Init     func(string) error
	Callback func(int64, int)
	End      func()
}

func (my *MytokenProvider) GetMytokenByAuthorizationFlow(issuer string, restrictions api.Restrictions, capabilities, subtokenCapabilities api.Capabilities, responseType, name string, callbacks PollingCallbacks) (string, error) {
	authRes, err := my.InitAuthorizationFlow(issuer, restrictions, capabilities, subtokenCapabilities, responseType, name)
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

func (my *MytokenProvider) InitAuthorizationFlow(issuer string, restrictions api.Restrictions, capabilities, subtokenCapabilities api.Capabilities, responseType, name string) (*api.AuthCodeFlowResponse, error) {
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
			OIDCFlow:             api.OIDCFlowAuthorizationCode,
		},
		RedirectType: "native",
	}
	resp, err := httpClient.Do().R().SetBody(req).SetResult(&api.AuthCodeFlowResponse{}).SetError(&api.Error{}).Post(my.MytokenEndpoint)
	if err != nil {
		return nil, newMytokenErrorFromError("error while sending http request", err)
	}
	if e := resp.Error(); e != nil {
		if errRes := e.(*api.Error); errRes != nil && errRes.Error != "" {
			return nil, &MytokenError{
				err:          errRes.Error,
				errorDetails: errRes.ErrorDescription,
			}
		}
	}
	authRes, ok := resp.Result().(*api.AuthCodeFlowResponse)
	if !ok {
		return nil, &MytokenError{
			err: unexpectedResponse,
		}
	}
	return authRes, nil
}

func (my *MytokenProvider) Poll(res api.PollingInfo, callback func(int64, int)) (string, error) {
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

func (my *MytokenProvider) PollOnce(pollingCode string) (string, bool, error) {
	req := api.PollingCodeRequest{
		GrantType:   api.GrantTypePollingCode,
		PollingCode: pollingCode,
	}

	tok, err := my.GetMytoken(req)
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
