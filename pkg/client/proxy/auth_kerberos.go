package proxy

import (
	"bytes"
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
)

// OID for NTLMSSP: 1.3.6.1.4.1.311.2.2.10
var oidNTLMSSP = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}

// OID for SPNEGO: 1.3.6.1.5.5.2
var oidSPNEGO = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}

// NegTokenInit represents SPNEGO negotiation initiation (RFC 4178).
type negTokenInitASN1 struct {
	MechTypes   []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags    asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken   []byte                  `asn1:"explicit,optional,tag:2"`
	MechListMIC []byte                  `asn1:"explicit,optional,tag:3"`
}

// SPNEGOHeader wraps NegTokenInit inside the GSS-API InitialContextToken.
type spnegoInitialContextToken struct {
	ThisMech   asn1.ObjectIdentifier
	InnerToken negTokenInitASN1 `asn1:"explicit,tag:0"`
}

// negTokenRespASN1 represents SPNEGO negotiation response.
type negTokenRespASN1 struct {
	NegState      asn1.Enumerated       `asn1:"explicit,optional,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,tag:3"`
}

// HasKerberosCredentials checks whether standard Kerberos ccache is present in the environment.
func HasKerberosCredentials() bool {
	if ccache := os.Getenv("KRB5CCNAME"); ccache != "" {
		if strings.HasPrefix(ccache, "FILE:") {
			ccache = strings.TrimPrefix(ccache, "FILE:")
		}
		if _, err := os.Stat(ccache); err == nil {
			return true
		}
	}
	uid := os.Getuid()
	defaultPath := fmt.Sprintf("/tmp/krb5cc_%d", uid)
	if _, err := os.Stat(defaultPath); err == nil {
		return true
	}
	return false
}

// BuildSPNEGONTLMInit wraps an NTLM Type 1 negotiate token into a SPNEGO NegTokenInit.
func BuildSPNEGONTLMInit(domain, workstation string) (string, error) {
	type1B64 := BuildNTLMType1(domain, workstation)
	type1Bytes, err := base64.StdEncoding.DecodeString(type1B64)
	if err != nil {
		return "", err
	}

	initToken := negTokenInitASN1{
		MechTypes: []asn1.ObjectIdentifier{oidNTLMSSP},
		MechToken: type1Bytes,
	}

	wrapper := spnegoInitialContextToken{
		ThisMech:   oidSPNEGO,
		InnerToken: initToken,
	}

	derBytes, err := asn1.Marshal(wrapper)
	if err != nil {
		// Fallback: manual ASN.1 framing if complex struct marshalling varies
		var buf bytes.Buffer
		buf.Write([]byte{0x60}) // Application 0 (GSS-API context token)
		mechOID, _ := asn1.Marshal(oidSPNEGO)
		mechTokenDER, _ := asn1.Marshal(type1Bytes)
		mechTypeDER, _ := asn1.Marshal([]asn1.ObjectIdentifier{oidNTLMSSP})

		var inner bytes.Buffer
		inner.Write([]byte{0xa0}) // tag 0: mechTypes
		inner.Write([]byte{byte(len(mechTypeDER))})
		inner.Write(mechTypeDER)

		inner.Write([]byte{0xa2}) // tag 2: mechToken
		inner.Write([]byte{byte(len(mechTokenDER))})
		inner.Write(mechTokenDER)

		innerBytes := inner.Bytes()
		var negToken bytes.Buffer
		negToken.Write([]byte{0xa0}) // NegTokenInit tag 0
		negToken.Write([]byte{byte(len(innerBytes))})
		negToken.Write(innerBytes)

		fullPayload := append(mechOID, negToken.Bytes()...)
		buf.Write([]byte{byte(len(fullPayload))})
		buf.Write(fullPayload)
		derBytes = buf.Bytes()
	}

	return "Negotiate " + base64.StdEncoding.EncodeToString(derBytes), nil
}

// ExtractSPNEGOMechToken unpacks a response token from a SPNEGO NegTokenResp.
func ExtractSPNEGOMechToken(header string) ([]byte, error) {
	header = strings.TrimSpace(header)
	if strings.HasPrefix(strings.ToLower(header), "negotiate ") {
		header = strings.TrimSpace(header[10:])
	}

	data, err := base64.StdEncoding.DecodeString(header)
	if err != nil {
		return nil, fmt.Errorf("failed to decode SPNEGO base64: %w", err)
	}

	// If raw NTLMSSP payload was directly returned
	if bytes.Contains(data, ntlmSignature) {
		idx := bytes.Index(data, ntlmSignature)
		return data[idx:], nil
	}

	var resp negTokenRespASN1
	_, err = asn1.Unmarshal(data, &resp)
	if err == nil && len(resp.ResponseToken) > 0 {
		return resp.ResponseToken, nil
	}

	return nil, errors.New("failed to extract mechToken from SPNEGO response")
}
