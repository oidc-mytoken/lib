package mytokenlib

import (
	"errors"
	"fmt"
	"time"

	"github.com/oidc-mytoken/api/v0"
)

// PollingCallbacks is a struct holding callback related to the polling in the authorization code flow.
// The Init function takes the authorization url and is called before starting polling the server; this callback
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

// pollOnce sends a single polling request with the passed pollingCode to the specified Endpoint and unmarshalls the
// response into the resp interface{}
func pollOnce(pollingCode string, endpoint Endpoint, resp interface{}) (bool, error) {
	req := api.PollingCodeRequest{
		GrantType:   api.GrantTypePollingCode,
		PollingCode: pollingCode,
	}
	err := endpoint.DoHTTPRequest("POST", req, resp)
	if err == nil {
		return true, nil
	}
	var myErr *MytokenError
	if errors.As(err, &myErr) && myErr.err == api.ErrorStrAuthorizationPending {
		err = nil
	}
	return false, err
}

// poll performs the polling for the final response in a polling-based flow using the passed api.PollingInfo.
// The callback function takes the polling interval and the number of iteration as parameters; it is called for each
// polling attempt where the final mytoken could not yet be obtained (but no error occurred); it is usually used to
// print progress output.
func poll(info api.PollingInfo, callback func(int64, int), endpoint Endpoint, resp interface{}) (bool, error) {
	expires := time.Now().Add(time.Duration(info.PollingCodeExpiresIn) * time.Second)
	interval := info.PollingInterval
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
		set, err := pollOnce(info.PollingCode, endpoint, resp)
		if err != nil {
			return set, err
		}
		if set {
			return set, nil
		}
		callback(info.PollingInterval, i)
		i++
	}
	return false, fmt.Errorf("polling code expired")
}
