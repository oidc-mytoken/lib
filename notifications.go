package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// NotificationsEndpoint is type representing a mytoken server's Notifications Endpoint
type NotificationsEndpoint struct {
	endpoint string
}

func newNotificationsEndpoint(endpoint string) *NotificationsEndpoint {
	return &NotificationsEndpoint{endpoint: endpoint}
}

// DoHTTPRequest performs an http request to the notifications endpoint
func (n NotificationsEndpoint) DoHTTPRequest(method string, req, resp interface{}) error {
	return doHTTPRequest(method, n.endpoint, req, resp)
}

// DoHTTPRequestWithAuth performs an http request to the notifications endpoint with mytoken authorization
func (n NotificationsEndpoint) DoHTTPRequestWithAuth(method string, req, resp interface{}, mytoken string) error {
	return doHTTPRequestWithAuth(method, n.endpoint, req, resp, mytoken)
}

// APIList lists all notifications
func (n NotificationsEndpoint) APIList(mytoken string) (resp api.NotificationsListResponse, err error) {
	err = n.DoHTTPRequestWithAuth("GET", nil, &resp, mytoken)
	return
}

// APICreate creates a new notification subscription
func (n NotificationsEndpoint) APICreate(mytoken string, req api.SubscribeNotificationRequest) (resp api.NotificationsCreateResponse, err error) {
	err = n.DoHTTPRequestWithAuth("POST", req, &resp, mytoken)
	return
}

// APIUpdate updates notification classes and/or tags
func (n NotificationsEndpoint) APIUpdate(mytoken, managementCode string, req api.NotificationUpdateRequest) (resp api.OnlyTokenUpdateResponse, err error) {
	url := n.endpoint + "/" + managementCode + "/nc"
	err = doHTTPRequestWithAuth("PUT", url, req, &resp, mytoken)
	return
}

// APIDelete deletes a notification by management code
func (n NotificationsEndpoint) APIDelete(mytoken, managementCode string) (resp api.OnlyTokenUpdateResponse, err error) {
	url := n.endpoint + "/" + managementCode
	err = doHTTPRequestWithAuth("DELETE", url, nil, &resp, mytoken)
	return
}

// APIAddToken adds a token to a notification
func (n NotificationsEndpoint) APIAddToken(mytoken, managementCode string, req api.NotificationAddTokenRequest) (resp api.OnlyTokenUpdateResponse, err error) {
	url := n.endpoint + "/" + managementCode + "/token"
	err = doHTTPRequestWithAuth("POST", url, req, &resp, mytoken)
	return
}

// APIRemoveToken removes a token from a notification
func (n NotificationsEndpoint) APIRemoveToken(mytoken, managementCode string, req api.NotificationRemoveTokenRequest) (resp api.OnlyTokenUpdateResponse, err error) {
	url := n.endpoint + "/" + managementCode + "/token"
	err = doHTTPRequestWithAuth("DELETE", url, req, &resp, mytoken)
	return
}
