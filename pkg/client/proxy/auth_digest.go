package proxy

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// DigestChallenge represents parsed fields from Proxy-Authenticate: Digest ...
type DigestChallenge struct {
	Realm     string
	Nonce     string
	QOP       string
	Algorithm string
	Opaque    string
}

// ParseDigestChallenge extracts key-value directives from a Digest challenge string.
func ParseDigestChallenge(header string) DigestChallenge {
	c := DigestChallenge{
		Algorithm: "MD5",
	}
	header = strings.TrimSpace(header)
	if strings.HasPrefix(strings.ToLower(header), "digest ") {
		header = strings.TrimSpace(header[7:])
	}

	parts := splitDirectives(header)
	for k, v := range parts {
		switch strings.ToLower(k) {
		case "realm":
			c.Realm = v
		case "nonce":
			c.Nonce = v
		case "qop":
			c.QOP = v
		case "algorithm":
			c.Algorithm = v
		case "opaque":
			c.Opaque = v
		}
	}
	return c
}

func splitDirectives(s string) map[string]string {
	res := make(map[string]string)
	for len(s) > 0 {
		s = strings.TrimSpace(s)
		commaIdx := strings.Index(s, ",")
		equalIdx := strings.Index(s, "=")
		if equalIdx == -1 {
			break
		}

		key := strings.TrimSpace(s[:equalIdx])
		rest := strings.TrimSpace(s[equalIdx+1:])

		var val string
		if strings.HasPrefix(rest, "\"") {
			// Quoted string
			quoteEnd := strings.Index(rest[1:], "\"")
			if quoteEnd != -1 {
				val = rest[1 : quoteEnd+1]
				after := rest[quoteEnd+2:]
				if nextComma := strings.Index(after, ","); nextComma != -1 {
					s = after[nextComma+1:]
				} else {
					s = ""
				}
			} else {
				val = strings.Trim(rest, "\"")
				s = ""
			}
		} else {
			// Unquoted token
			if commaIdx != -1 && commaIdx > equalIdx {
				val = strings.TrimSpace(rest[:commaIdx-equalIdx-1])
				s = rest[commaIdx-equalIdx:]
				if len(s) > 0 && s[0] == ',' {
					s = s[1:]
				}
			} else {
				val = rest
				s = ""
			}
		}
		res[key] = val
	}
	return res
}

func md5Hex(data string) string {
	h := md5.Sum([]byte(data))
	return hex.EncodeToString(h[:])
}

// BuildDigestAuthHeader computes the RFC 7616 Digest response for HTTP CONNECT.
func BuildDigestAuthHeader(username, password, targetAddr string, ch DigestChallenge, nc int) string {
	ncStr := fmt.Sprintf("%08x", nc)
	cnonceBytes := make([]byte, 8)
	_, _ = rand.Read(cnonceBytes)
	cnonce := hex.EncodeToString(cnonceBytes)

	ha1 := md5Hex(fmt.Sprintf("%s:%s:%s", username, ch.Realm, password))
	ha2 := md5Hex(fmt.Sprintf("CONNECT:%s", targetAddr))

	var response string
	hasAuthQOP := strings.Contains(strings.ToLower(ch.QOP), "auth")

	if hasAuthQOP {
		response = md5Hex(fmt.Sprintf("%s:%s:%s:%s:auth:%s", ha1, ch.Nonce, ncStr, cnonce, ha2))
	} else {
		response = md5Hex(fmt.Sprintf("%s:%s:%s", ha1, ch.Nonce, ha2))
	}

	var sb strings.Builder
	sb.WriteString("Digest ")
	sb.WriteString(fmt.Sprintf("username=\"%s\", ", username))
	sb.WriteString(fmt.Sprintf("realm=\"%s\", ", ch.Realm))
	sb.WriteString(fmt.Sprintf("nonce=\"%s\", ", ch.Nonce))
	sb.WriteString(fmt.Sprintf("uri=\"%s\", ", targetAddr))
	sb.WriteString(fmt.Sprintf("response=\"%s\"", response))

	if hasAuthQOP {
		sb.WriteString(fmt.Sprintf(", qop=auth, nc=%s, cnonce=\"%s\"", ncStr, cnonce))
	}
	if ch.Opaque != "" {
		sb.WriteString(fmt.Sprintf(", opaque=\"%s\"", ch.Opaque))
	}
	if ch.Algorithm != "" {
		sb.WriteString(fmt.Sprintf(", algorithm=%s", ch.Algorithm))
	}

	return sb.String()
}
