package sdk

import (
	"fmt"

	log "github.com/sirupsen/logrus"

	"github.com/pkg/errors"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/pcrs"
)

type FunctionIDRequest struct {
	URL          string
	FunctionName string
	FunctionAuth entities.FunctionAuth
	PcrSlice     []string

	// For development use only: skips validating TLS certificate from the URL
	Insecure bool
}

func GetFunctionID(functionReq FunctionIDRequest) (string, error) {
	endpoint := fmt.Sprintf("%s/v1/function?name=%s", functionReq.URL, functionReq.FunctionName)

	authProtocolType := "cape.runtime"
	if functionReq.FunctionAuth.Type == entities.AuthenticationTypeFunctionToken {
		authProtocolType = "cape.function"
	}

	conn, err := doDial(endpoint, functionReq.Insecure, authProtocolType, functionReq.FunctionAuth.Token)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	nonce, err := crypto.GetNonce()
	if err != nil {
		return "", err
	}

	p := getProtocol(conn)

	req := entities.StartRequest{Nonce: []byte(nonce)}
	log.Debug("\n> Sending Nonce")
	err = p.WriteStart(req)
	if err != nil {
		return "", errors.Wrap(err, "error writing functionID request")
	}

	log.Debug("* Waiting for attestation document...")

	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		log.Println("error reading attestation doc")
		return "", err
	}

	log.Debug("< Downloading AWS Root Certificate")
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return "", err
	}

	log.Debug("< Auth Completed. Received Attestation Document")
	doc, _, err := attest.Attest(attestDoc, rootCert)
	if err != nil {
		log.Println("error attesting")
		return "", err
	}

	err = pcrs.VerifyPCRs(pcrs.SliceToMapStringSlice(functionReq.PcrSlice), doc)
	if err != nil {
		log.Println("error verifying PCRs")
		return "", err
	}

	// read the function id
	deployment, err := p.ReadDeploymentInfo()
	if err != nil {
		log.Println("error getting functionID")
		return "", err
	}

	return deployment.ID.String(), nil
}
