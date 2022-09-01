package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// MytokenServer is a type describing a mytoken server instance
type MytokenServer struct {
	ServerMetadata api.MytokenConfiguration
	AccessToken    *AccessTokenEndpoint
	Mytoken        *MytokenEndpoint
	Revocation     *RevocationEndpoint
	Tokeninfo      *TokeninfoEndpoint
	Transfer       *TransferEndpoint
	UserSettings   *UserSettingsEndpoint
}

// Endpoint is an interface for mytoken endpoints
type Endpoint interface {
	DoHTTPRequest(method string, req interface{}, resp interface{}) error
}

// NewMytokenServer creates a new MytokenServer
func NewMytokenServer(url string) (*MytokenServer, error) {
	configEndpoint := url
	if url[len(url)-1] != '/' {
		configEndpoint += "/"
	}
	configEndpoint += ".well-known/mytoken-configuration"
	var respData api.MytokenConfiguration
	if err := doHTTPRequest("GET", configEndpoint, nil, &respData); err != nil {
		return nil, err
	}
	server := &MytokenServer{
		ServerMetadata: respData,
		AccessToken:    newAccessTokenEndpoint(respData.AccessTokenEndpoint),
		Mytoken:        newMytokenEndpoint(respData.MytokenEndpoint),
		Revocation:     newRevocationEndpoint(respData.RevocationEndpoint),
		Tokeninfo:      newTokeninfoEndpoint(respData.TokeninfoEndpoint),
		Transfer:       newTransferEndpoint(respData.TokenTransferEndpoint),
	}
	var err error
	server.UserSettings, err = newUserSettingsEndpoint(respData.UserSettingsEndpoint)
	if err != nil && err.Error() == "not_found" {
		err = nil
	}
	return server, err
}
