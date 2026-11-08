package evasion

import (
	"encoding/base64"
	"encoding/hex"
)

func EncodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func EncodeBase64URL(data []byte) string {
	return base64.URLEncoding.EncodeToString(data)
}

func DecodeBase64URL(s string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(s)
}

func EncodeHex(data []byte) string {
	return hex.EncodeToString(data)
}

func DecodeHex(s string) ([]byte, error) {
	return hex.DecodeString(s)
}
