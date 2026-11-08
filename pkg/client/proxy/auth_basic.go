package proxy

import (
	"encoding/base64"
)

// BuildBasicAuthHeader formats an RFC 7617 Basic Proxy-Authorization header.
func BuildBasicAuthHeader(username, password string) string {
	creds := username + ":" + password
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(creds))
}
