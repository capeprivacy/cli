package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	log "github.com/sirupsen/logrus"
)

func GetNonce() (string, error) {
	buf := make([]byte, 16)

	if _, err := rand.Reader.Read(buf); err != nil {
		return "", fmt.Errorf("failed to get nonce: %v", err)
	}

	nonce := base64.StdEncoding.EncodeToString(buf)
	log.Debugf("* Generated Nonce: %s", nonce)
	return nonce, nil
}
