package sdk

import "C"
import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/capeprivacy/cli/attest"
	"github.com/capeprivacy/cli/config"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/pcrs"
	czip "github.com/capeprivacy/cli/zip"
)

const storedFunctionMaxBytes = 1_000_000_000

type OversizeFunctionError struct {
	bytes int64
}

func (e OversizeFunctionError) Error() string {
	return fmt.Sprintf("deployment (%d bytes) exceeds size limit of %d bytes", e.bytes, storedFunctionMaxBytes)
}

type Client struct {
	cfg *config.Config
}

func NewClient(cfg *config.Config) (*Client, error) {
	return &Client{cfg: cfg}, nil
}

type DeployHandler interface {
	ValidateFunction()
	Zipping()
	Dialing()
	SendNonce()
	Attesting()
	EncryptingFunction()
	Uploading()
	IDReturned(id string)
}

func (c *Client) Deploy(dh DeployHandler, function string) error {
	dh.ValidateFunction()
	file, err := os.Open(function)
	if err != nil {
		return err
	}

	st, err := file.Stat()
	if err != nil {
		return err
	}

	isZip := false
	var fileSize int64
	if st.IsDir() {
		_, err = file.Readdirnames(1)
		if err != nil {
			return err
		}
		fileSize, err = dirSize(function)
		if err != nil {
			return err
		}
	} else {
		fileExtension := filepath.Ext(function)
		if fileExtension != ".zip" {
			return err
		}
		isZip = true
		zSize, err := zipSize(function)
		if err != nil {
			return err
		}

		fileSize = int64(zSize)
	}

	if fileSize > storedFunctionMaxBytes {
		return OversizeFunctionError{bytes: fileSize}
	}

	err = file.Close()
	if err != nil {
		return err
	}

	var reader io.Reader

	if isZip {
		f, err := os.Open(function)
		if err != nil {
			return err
		}

		reader = f
	} else {
		dh.Zipping()
		buf, err := czip.Create(function)
		if err != nil {
			return err
		}

		reader = bytes.NewBuffer(buf)
	}

	// TODO public function
	//keyReq, err := GetKeyRequest(pcrSlice)
	//if err != nil {
	//	return "", nil, err
	//}

	endpoint := fmt.Sprintf("%s/v1/deploy", c.cfg.EnclaveHost)
	dh.Dialing()
	conn, err := doDial(endpoint, c.cfg.Insecure, "cape.runtime", c.cfg.AuthToken)
	if err != nil {
		return err
	}

	p := getProtocol(conn)
	nonce, err := crypto.GetNonce()
	if err != nil {
		return err
	}

	dh.SendNonce()
	r := entities.StartRequest{Nonce: []byte(nonce)}
	if err := p.WriteStart(r); err != nil {
		return err
	}

	dh.Attesting()
	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		return err
	}

	// dh.RootCert()
	rootCert, err := attest.GetRootAWSCert()
	if err != nil {
		return err
	}

	doc, _, err := attest.Attest(attestDoc, rootCert)
	if err != nil {
		return err
	}

	// dh.VerifyPCRs()
	err = pcrs.VerifyPCRs(pcrs.SliceToMapStringSlice(nil), doc)
	if err != nil {
		return err
	}

	dh.EncryptingFunction()
	hasher := sha256.New()
	// tReader is used to stream data to the hasher function.
	tReader := io.TeeReader(reader, hasher)
	plaintext, err := io.ReadAll(tReader)
	if err != nil {
		return err
	}

	capeKeyFile := filepath.Join(c.cfg.LocalConfigDir, c.cfg.LocalCapeKeyFileName)

	keyReq := KeyRequest{
		URL:          c.cfg.EnclaveHost,
		Insecure:     c.cfg.Insecure,
		FunctionAuth: entities.FunctionAuth{Type: entities.AuthenticationTypeAuth0, Token: c.cfg.AuthToken},
		ConfigDir:    c.cfg.LocalConfigDir,
		CapeKeyFile:  capeKeyFile,
		PcrSlice:     nil, // TODO -- user can specify these
	}

	// hash := hasher.Sum(nil)
	ciphertext, err := EncryptBytes(keyReq, plaintext)
	if err != nil {
		return err
	}

	dh.Uploading()
	if err := p.WriteFunctionInfo("", function); err != nil {
		return err
	}

	err = writeFunction(conn, bytes.NewBuffer(ciphertext))
	if err != nil {
		return err
	}

	resData, err := p.ReadDeploymentResults()
	if err != nil {
		return err
	}

	dh.IDReturned(resData.ID)

	return nil
}

func dirSize(path string) (int64, error) {
	var size int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if !info.IsDir() {
			size += info.Size()
		}
		return nil
	})
	return size, err
}

func zipSize(path string) (uint64, error) {
	var size uint64
	r, err := zip.OpenReader(path)
	if err != nil {
		return 0, err
	}
	for _, f := range r.File {
		size += f.UncompressedSize64
	}

	return size, nil
}
