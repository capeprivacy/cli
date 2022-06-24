package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GetNonce() (string, error) {
	buf := make([]byte, 16)

	if _, err := rand.Reader.Read(buf); err != nil {
		return "", fmt.Errorf("failed to get nonce: %v", err)
	}

	return base64.StdEncoding.EncodeToString(buf), nil
}
