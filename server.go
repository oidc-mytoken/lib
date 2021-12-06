package mytokenlib

import (
	"context"
	"net/http"

	"github.com/oidc-mytoken/api/v0"
)

// MytokenServer is a type describing a mytoken server instance
type MytokenServer struct {
	api.MytokenConfiguration
}

var httpClient = &http.Client{}
var ctx = context.Background()

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
	return &MytokenServer{
		MytokenConfiguration: respData,
	}, nil
}

// SetClient sets the http.Client used to make API requests
func SetClient(client *http.Client) {
	httpClient = client
}

// SetContext sets a context.Context used for all API requests
func SetContext(contxt context.Context) {
	ctx = contxt
}
