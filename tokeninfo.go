package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

func (my *MytokenServer) TokeninfoIntrospect(mytoken string) (*api.TokeninfoIntrospectResponse, error) {
	req := api.TokenInfoRequest{
		Action:  api.TokeninfoActionIntrospect,
		Mytoken: mytoken,
	}
	var resp api.TokeninfoIntrospectResponse
	if err := doHTTPRequest("POST", my.TokeninfoEndpoint, req, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}
func (my *MytokenServer) TokeninfoHistory(mytoken *string) (api.EventHistory, error) {
	req := api.TokenInfoRequest{
		Action:  api.TokeninfoActionEventHistory,
		Mytoken: *mytoken,
	}
	var resp api.TokeninfoHistoryResponse
	if err := doHTTPRequest("POST", my.TokeninfoEndpoint, req, &resp); err != nil {
		return nil, err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return resp.EventHistory, nil
}
func (my *MytokenServer) TokeninfoSubtokens(mytoken *string) (*api.MytokenEntryTree, error) {
	req := api.TokenInfoRequest{
		Action:  api.TokeninfoActionSubtokenTree,
		Mytoken: *mytoken,
	}
	var resp api.TokeninfoTreeResponse
	if err := doHTTPRequest("POST", my.TokeninfoEndpoint, req, &resp); err != nil {
		return nil, err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return &resp.Tokens, nil
}
func (my *MytokenServer) TokeninfoListMytokens(mytoken *string) ([]api.MytokenEntryTree, error) {
	req := api.TokenInfoRequest{
		Action:  api.TokeninfoActionListMytokens,
		Mytoken: *mytoken,
	}
	var resp api.TokeninfoListResponse
	if err := doHTTPRequest("POST", my.TokeninfoEndpoint, req, &resp); err != nil {
		return nil, err
	}
	if resp.TokenUpdate != nil {
		*mytoken = resp.TokenUpdate.Mytoken
	}
	return resp.Tokens, nil
}
