package sdk

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/gorilla/websocket"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli"

	"github.com/capeprivacy/attest/attest"
	"github.com/capeprivacy/cli/crypto"
	"github.com/capeprivacy/cli/entities"
	"github.com/capeprivacy/cli/pcrs"
	proto "github.com/capeprivacy/cli/protocol"
	czip "github.com/capeprivacy/cli/zip"
)

const storedFunctionMaxBytes = 1_000_000_000

type OversizeFunctionError struct {
	bytes int64
}

func (e OversizeFunctionError) Error() string {
	return fmt.Sprintf("deployment (%d bytes) exceeds size limit of %d bytes", e.bytes, storedFunctionMaxBytes)
}

type protocol interface {
	WriteStart(request entities.StartRequest) error
	ReadAttestationDoc() ([]byte, error)
	ReadRunResults() (*cli.RunResult, error)
	WriteBinary([]byte) error
	WriteFunctionInfo(name string, public bool) error
	ReadDeploymentResults() (*entities.SetDeploymentIDRequest, error)
}

func getProtocol(ws *websocket.Conn) protocol {
	return proto.Protocol{Websocket: ws}
}

type DeployRequest struct {
	URL       string
	Name      string
	Reader    io.Reader
	PcrSlice  []string
	Public    bool
	AuthToken string

	// For development use only: skips validating TLS certificate from the URL
	Insecure bool
}

// Deploy encrypts the given function data within a secure enclave and stores the encrypted function for future use.
// Returns a function ID upon successful deployment. The stored function can only be decrypted within an enclave.
func Deploy(req DeployRequest, keyReq KeyRequest) (string, []byte, error) {
	endpoint := fmt.Sprintf("%s/v1/deploy", req.URL)
	log.Info("Deploying function to Cape ...")

	conn, err := doDial(endpoint, req.Insecure, "cape.runtime", req.AuthToken)
	if err != nil {
		return "", nil, err
	}
	defer func() {
		_ = conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		conn.Close()
	}()

	p := getProtocol(conn)

	nonce, err := crypto.GetNonce()
	if err != nil {
		return "", nil, err
	}

	r := entities.StartRequest{Nonce: nonce}
	log.Debug("\n> Sending Nonce and Auth Token")
	if err := p.WriteStart(r); err != nil {
		log.Error("error writing deploy request")
		return "", nil, err
	}

	log.Debug("* Waiting for attestation document...")

	attestDoc, err := p.ReadAttestationDoc()
	if err != nil {
		return "", nil, err
	}

	verifier := attest.NewVerifier()

	log.Debug("< Attestation document")
	doc, err := verifier.Verify(attestDoc, nonce)
	if err != nil {
		log.Error("error attesting")
		return "", nil, err
	}

	err = pcrs.VerifyPCRs(pcrs.SliceToMapStringSlice(req.PcrSlice), doc)
	if err != nil {
		log.Println("error verifying PCRs")
		return "", nil, err
	}

	hasher := sha256.New()
	// tReader is used to stream data to the hasher function.
	tReader := io.TeeReader(req.Reader, hasher)
	plaintext, err := io.ReadAll(tReader)
	if err != nil {
		log.Error("error reading plaintext function")
		return "", nil, err
	}

	// Print out the hash to the user.
	hash := hasher.Sum(nil)

	ciphertext, err := EncryptBytes(keyReq, plaintext)
	if err != nil {
		log.Error("error encrypting function")
		return "", nil, err
	}

	log.Debug("\n> Sending Function Info")
	if err := p.WriteFunctionInfo(req.Name, req.Public); err != nil {
		log.Error("error sending function info key")
		return "", nil, err
	}

	log.Debug("\n> Deploying Encrypted Function")
	err = writeFunction(conn, bytes.NewBuffer(ciphertext))
	if err != nil {
		return "", nil, err
	}

	log.Debug("* Waiting for deploy response...")

	resData, err := p.ReadDeploymentResults()
	if err != nil {
		return "", nil, err
	}
	log.Debugf("< Received Deploy Response: ID: %s", resData.ID)

	return resData.ID, hash, nil
}

func writeFunction(conn *websocket.Conn, reader io.Reader) error {
	writer, err := conn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		log.Errorf("error getting writer for function: %v", err)
		return err
	}
	defer writer.Close()

	_, err = io.Copy(writer, reader)
	if err != nil {
		return err
	}

	return nil
}

// ProcessUserFunction takes a string path and produces a io.Reader to zipped function.
// It could take both a folder as well as a zip file.
func ProcessUserFunction(path string) (io.Reader, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to read function directory or file: %w", err)
	}

	st, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("unable to read function file or directory: %w", err)
	}

	isZip := false
	var fileSize int64
	if st.IsDir() {
		_, err = file.Readdirnames(1)
		if err != nil {
			return nil, fmt.Errorf("please pass in a non-empty directory: %w", err)
		}
		fileSize, err = dirSize(path)
		if err != nil {
			return nil, fmt.Errorf("error reading file size: %w", err)
		}
	} else {
		// Check if file ends with ".zip" extension.
		fileExtension := filepath.Ext(path)
		if fileExtension != ".zip" {
			return nil, fmt.Errorf("expected argument %s to be a zip file or directory", path)
		}
		isZip = true
		zSize, err := zipSize(path)
		if err != nil {
			return nil, err
		}

		fileSize = int64(zSize)
	}

	log.Debugf("Deployment size: %d bytes", fileSize)
	if fileSize > storedFunctionMaxBytes {
		err = OversizeFunctionError{bytes: fileSize}
		log.Error(err.Error())
		return nil, err
	}

	err = file.Close()
	if err != nil {
		return nil, fmt.Errorf("something went wrong: %w", err)
	}

	var reader io.Reader

	if isZip {
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("unable to read function file: %w", err)
		}

		reader = f
	} else {
		buf, err := czip.Create(path)
		if err != nil {
			return nil, err
		}

		reader = bytes.NewBuffer(buf)
	}
	return reader, nil
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
