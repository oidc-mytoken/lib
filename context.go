package mytokenlib

import (
	"context"
	"net/http"
)

var ctx = context.Background()
var httpClient = &http.Client{}
var userAgent = "mytokenlib"

// ContextKeyUserAgent is used to set a useragent string in the context
const ContextKeyUserAgent = "mytokenlib-user-agent"

// SetClient sets the http.Client used to make API requests
func SetClient(client *http.Client) {
	httpClient = client
}

// SetContext sets a context.Context used for all API requests
func SetContext(contxt context.Context) {
	ctx = contxt
	s, ok := ctx.Value(ContextKeyUserAgent).(string)
	if ok {
		userAgent = s
	}
}
