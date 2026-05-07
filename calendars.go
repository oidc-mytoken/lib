package mytokenlib

import (
	"github.com/oidc-mytoken/api/v0"
)

// CalendarsEndpoint is type representing a mytoken server's Calendars Endpoint
type CalendarsEndpoint struct {
	endpoint string
}

func newCalendarsEndpoint(endpoint string) *CalendarsEndpoint {
	return &CalendarsEndpoint{endpoint: endpoint}
}

// DoHTTPRequest performs an http request to the calendars endpoint
func (c CalendarsEndpoint) DoHTTPRequest(method string, req, resp interface{}) error {
	return doHTTPRequest(method, c.endpoint, req, resp)
}

// DoHTTPRequestWithAuth performs an http request to the calendars endpoint with mytoken authorization
func (c CalendarsEndpoint) DoHTTPRequestWithAuth(method string, req, resp interface{}, mytoken string) error {
	return doHTTPRequestWithAuth(method, c.endpoint, req, resp, mytoken)
}

// APIList lists all calendars
func (c CalendarsEndpoint) APIList(mytoken string) (resp api.CalendarListResponse, err error) {
	err = c.DoHTTPRequestWithAuth("GET", nil, &resp, mytoken)
	return
}

// APICreate creates a new calendar
func (c CalendarsEndpoint) APICreate(mytoken string, req api.CreateCalendarRequest) (resp api.CalendarInfo, err error) {
	err = c.DoHTTPRequestWithAuth("POST", req, &resp, mytoken)
	return
}

// APIDelete deletes a calendar by ID
func (c CalendarsEndpoint) APIDelete(mytoken, calendarID string) (resp api.OnlyTokenUpdateResponse, err error) {
	url := c.endpoint + "/" + calendarID
	err = doHTTPRequestWithAuth("DELETE", url, nil, &resp, mytoken)
	return
}

// APISubscribe subscribes a mytoken to a calendar
func (c CalendarsEndpoint) APISubscribe(mytoken, calendarID string, req api.AddMytokenToCalendarRequest) (resp api.OnlyTokenUpdateResponse, err error) {
	url := c.endpoint + "/" + calendarID
	err = doHTTPRequestWithAuth("POST", url, req, &resp, mytoken)
	return
}

// APIUnsubscribe unsubscribes from a calendar
func (c CalendarsEndpoint) APIUnsubscribe(mytoken, calendarID, momID string) (resp api.OnlyTokenUpdateResponse, err error) {
	url := c.endpoint + "/" + calendarID
	req := api.AddMytokenToCalendarRequest{MomID: momID}
	err = doHTTPRequestWithAuth("DELETE", url, req, &resp, mytoken)
	return
}

// APIUpdate updates calendar description and/or tags
func (c CalendarsEndpoint) APIUpdate(mytoken, calendarID string, req api.CreateCalendarRequest) (resp api.OnlyTokenUpdateResponse, err error) {
	url := c.endpoint + "/" + calendarID
	err = doHTTPRequestWithAuth("PUT", url, req, &resp, mytoken)
	return
}
