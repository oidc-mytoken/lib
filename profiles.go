package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// ProfilesAndTemplatesEndpoint is type representing a mytoken server's Profiles and Templates Endpoint
type ProfilesAndTemplatesEndpoint struct {
	endpoint string
}

func newProfilesAndTemplatesEndpoint(endpoint string) *ProfilesAndTemplatesEndpoint {
	return &ProfilesAndTemplatesEndpoint{endpoint: endpoint}
}

// APIGetGroups retrieves all available profile groups
func (p ProfilesAndTemplatesEndpoint) APIGetGroups() ([]string, error) {
	var groups []string
	err := p.DoHTTPRequest("GET", nil, &groups)
	return groups, err
}

// APIGetCapabilities retrieves capability templates for a group
func (p ProfilesAndTemplatesEndpoint) APIGetCapabilities(group string) ([]api.Profile, error) {
	var capabilities []api.Profile
	err := p.DoHTTPRequest("GET", nil, &capabilities, "/"+group+"/capabilities")
	return capabilities, err
}

// APIGetRestrictions retrieves restriction templates for a group
func (p ProfilesAndTemplatesEndpoint) APIGetRestrictions(group string) ([]api.Profile, error) {
	var restrictions []api.Profile
	err := p.DoHTTPRequest("GET", nil, &restrictions, "/"+group+"/restrictions")
	return restrictions, err
}

// APIGetRotation retrieves rotation templates for a group
func (p ProfilesAndTemplatesEndpoint) APIGetRotation(group string) ([]api.Profile, error) {
	var rotation []api.Profile
	err := p.DoHTTPRequest("GET", nil, &rotation, "/"+group+"/rotation")
	return rotation, err
}

// APIGetProfiles retrieves profiles for a group
func (p ProfilesAndTemplatesEndpoint) APIGetProfiles(group string) ([]api.Profile, error) {
	var profiles []api.Profile
	err := p.DoHTTPRequest("GET", nil, &profiles, "/"+group+"/profiles")
	return profiles, err
}

// DoHTTPRequest performs an http request to the profiles and templates endpoint
func (p ProfilesAndTemplatesEndpoint) DoHTTPRequest(method string, req, resp interface{}, pathSuffix ...string) error {
	url := p.endpoint
	if len(pathSuffix) > 0 {
		url += pathSuffix[0]
	}
	return doHTTPRequest(method, url, req, resp)
}
