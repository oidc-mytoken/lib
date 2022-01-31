package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// UserSettingsEndpoint is type representing a mytoken server's User Settings Endpoint and the actions that can be
// performed there.
type UserSettingsEndpoint struct {
	endpoint    string
	metadata    api.SettingsMetaData
	metadataSet bool
	Grants      *GrantsEndpoint
}

func newUserSettingsEndpoint(endpoint string) (*UserSettingsEndpoint, error) {
	s := &UserSettingsEndpoint{
		endpoint: endpoint,
	}
	if err := s.discover(); err != nil {
		return nil, err
	}
	s.Grants = newGrantsEndpoint(s.metadata.GrantTypeEndpoint)
	return s, nil
}

// DoHTTPRequest performs an http request to the user settings endpoint
func (s UserSettingsEndpoint) DoHTTPRequest(method string, req, resp interface{}) error {
	return doHTTPRequest(method, s.endpoint, req, resp)
}

func (s *UserSettingsEndpoint) discover() error {
	err := s.DoHTTPRequest("GET", nil, &s.metadata)
	if err != nil {
		s.metadataSet = false
		return err
	}
	s.metadataSet = true
	return nil
}

// MetaData returns the user settings endpoint's api.SettingsMetaData
func (s UserSettingsEndpoint) MetaData() (api.SettingsMetaData, error) {
	var err error
	if !s.metadataSet {
		err = s.discover()
	}
	return s.metadata, err
}
