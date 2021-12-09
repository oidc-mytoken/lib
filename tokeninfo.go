package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// TokeninfoEndpoint is type representing a mytoken server's Revocation Endpoint and the actions that can be
// performed there.
type TokeninfoEndpoint struct {
	endpoint string
}

func newTokeninfoEndpoint(endpoint string) *TokeninfoEndpoint {
	return &TokeninfoEndpoint{
		endpoint: endpoint,
	}
}

// DoHTTPRequest performs an http request to the tokeninfo endpoint
func (info TokeninfoEndpoint) DoHTTPRequest(method string, req interface{}, resp interface{}) error {
	return doHTTPRequest(method, info.endpoint, req, resp)
}

// Introspect introspects the passed mytoken
func (info TokeninfoEndpoint) Introspect(mytoken string) (*api.TokeninfoIntrospectResponse, error) {
	req := api.TokenInfoRequest{
		Action:  api.TokeninfoActionIntrospect,
		Mytoken: mytoken,
	}
	var resp api.TokeninfoIntrospectResponse
	if err := info.DoHTTPRequest("POST", req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// History obtains the event history for the passed mytoken.
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (info TokeninfoEndpoint) History(mytoken *string) (api.EventHistory, error) {
	req := api.TokenInfoRequest{
		Action:  api.TokeninfoActionEventHistory,
		Mytoken: *mytoken,
	}
	var resp api.TokeninfoHistoryResponse
	if err := info.DoHTTPRequest("POST", req, &resp); err != nil {
		return nil, err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return resp.EventHistory, nil
}

// Subtokens returns a api.MytokenEntryTree listing metadata about the passed mytoken and its children (
// recursively)
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (info TokeninfoEndpoint) Subtokens(mytoken *string) (*api.MytokenEntryTree, error) {
	req := api.TokenInfoRequest{
		Action:  api.TokeninfoActionSubtokenTree,
		Mytoken: *mytoken,
	}
	var resp api.TokeninfoTreeResponse
	if err := info.DoHTTPRequest("POST", req, &resp); err != nil {
		return nil, err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return &resp.Tokens, nil
}

// ListMytokens returns a slice of api.MytokenEntryTree listing metadata about all the user's mytoken and their
// children (recursively)
// If the used mytoken changes (due to token rotation), the passed variable is updated accordingly.
func (info TokeninfoEndpoint) ListMytokens(mytoken *string) ([]api.MytokenEntryTree, error) {
	req := api.TokenInfoRequest{
		Action:  api.TokeninfoActionListMytokens,
		Mytoken: *mytoken,
	}
	var resp api.TokeninfoListResponse
	if err := info.DoHTTPRequest("POST", req, &resp); err != nil {
		return nil, err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return resp.Tokens, nil
}
