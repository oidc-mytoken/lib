package mytokenlib

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/oidc-mytoken/api/v0"
)

const (
	errSendingHttpRequest    = "error while sending http request"
	errDecodingHttpResponse  = "could not decode response"
	errDecodingErrorResponse = "could not decode error response"
	errEncodingRequest       = "could not encode request"
)

const mimetypeJSON = "application/json"

func doHTTPRequest(method, url string, reqBody interface{}, responseData interface{}) error {
	return doHTTPRequestWithAuth(method, url, reqBody, responseData, "")
}

func doHTTPRequestWithAuth(
	method, url string, reqBody interface{}, responseData interface{},
	bearerAuth string,
) error {
	b := new(bytes.Buffer)
	if err := json.NewEncoder(b).Encode(reqBody); err != nil {
		return newMytokenErrorFromError(errEncodingRequest, err)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, b)
	if err != nil {
		return newMytokenErrorFromError(errSendingHttpRequest, err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", mimetypeJSON)
	}
	if responseData != nil {
		req.Header.Set("Accept", mimetypeJSON)
	}
	if bearerAuth != "" {
		req.Header.Set("Authorization", "Bearer "+bearerAuth)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return newMytokenErrorFromError(errSendingHttpRequest, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		var apiError api.Error
		if err = json.NewDecoder(resp.Body).Decode(&apiError); err != nil {
			return newMytokenErrorFromError(errDecodingErrorResponse, err)
		}
		return MytokenError{
			err:          apiError.Error,
			errorDetails: apiError.ErrorDescription,
		}
	}
	if responseData != nil && resp.ContentLength != 0 {
		if err = json.NewDecoder(resp.Body).Decode(responseData); err != nil {
			return newMytokenErrorFromError(errDecodingHttpResponse, err)
		}
	}
	return nil
}
