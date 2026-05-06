package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// TagsSettingsEndpoint is type representing a mytoken server's Tags Settings Endpoint
type TagsSettingsEndpoint struct {
	endpoint string
}

func newTagsSettingsEndpoint(endpoint string) *TagsSettingsEndpoint {
	return &TagsSettingsEndpoint{endpoint: endpoint}
}

// APIGet retrieves the user's tags
func (t TagsSettingsEndpoint) APIGet(mytoken string) (resp api.TagListingResponse, err error) {
	err = t.DoHTTPRequestWithAuth("GET", nil, &resp, mytoken)
	return
}

// APICreate creates a new tag with optional color
func (t TagsSettingsEndpoint) APICreate(mytoken, tagName, color string) (err error) {
	req := map[string]interface{}{}
	if color != "" {
		req["color"] = color
	}
	url := t.endpoint + "/" + tagName
	err = doHTTPRequestWithAuth("POST", url, req, nil, mytoken)
	return
}

// APIUpdate updates an existing tag
func (t TagsSettingsEndpoint) APIUpdate(mytoken, tagName, newTagName, color string) (resp api.OnlyTokenUpdateResponse, err error) {
	req := map[string]interface{}{}
	if newTagName != "" {
		req["tag"] = newTagName
	}
	if color != "" {
		req["color"] = color
	}
	url := t.endpoint + "/" + tagName
	err = doHTTPRequestWithAuth("PUT", url, req, &resp, mytoken)
	return
}

// APIDelete deletes a tag
func (t TagsSettingsEndpoint) APIDelete(mytoken, tagName string) (resp api.OnlyTokenUpdateResponse, err error) {
	url := t.endpoint + "/" + tagName
	err = doHTTPRequestWithAuth("DELETE", url, nil, &resp, mytoken)
	return
}

// DoHTTPRequest performs an http request to the tags settings endpoint
func (t TagsSettingsEndpoint) DoHTTPRequest(method string, req, resp interface{}) error {
	return doHTTPRequest(method, t.endpoint, req, resp)
}

// DoHTTPRequestWithAuth performs an http request to the tags settings endpoint with mytoken authorization
func (t TagsSettingsEndpoint) DoHTTPRequestWithAuth(method string, req, resp interface{}, mytoken string) error {
	return doHTTPRequestWithAuth(method, t.endpoint, req, resp, mytoken)
}
