package attest

import (
	"encoding/base64"
	"encoding/json"
)

type AttestationDoc struct {
	PublicKey string `json:"public_key"`
}

func Attest(attestation string) (*AttestationDoc, error) {
	by, err := base64.StdEncoding.DecodeString(attestation)
	if err != nil {
		return nil, err
	}

	doc := &AttestationDoc{}
	err = json.Unmarshal(by, doc)
	if err != nil {
		return nil, err
	}

	return doc, nil
}
