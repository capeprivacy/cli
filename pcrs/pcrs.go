package pcrs

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/capeprivacy/cli/attest"
	log "github.com/sirupsen/logrus"
)

type Measurements map[string]string

type EIFInfo struct {
	Measurements Measurements `json:"measurements"`
}

func DownloadEIF(bucket string, sentinelVersion string) (string, error) {
	sess := session.Must(session.NewSession())

	// Create a downloader with the session and default options
	downloader := s3manager.NewDownloader(sess)

	f, err := os.CreateTemp("", "sentinel")
	if err != nil {
		return "", err
	}
	defer f.Close()

	key := fmt.Sprintf("sentinel-runner-%s.eif", sentinelVersion)
	_, err = downloader.Download(f, &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	if err != nil {
		return "", err
	}

	return f.Name(), nil
}

func GetEIFInfo(basePath string) (*EIFInfo, error) {
	args := []string{
		"run",
		"-v", "/tmp:/eif",
		"capeprivacy/eif-builder:latest",
		"describe-eif",
		"--eif-path", fmt.Sprintf("/eif/%s", basePath),
	}
	cmd := exec.Command("docker", args...)
	res, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			log.WithError(ee).WithField("stderr", string(ee.Stderr)).Error("failed to get eif info")
		}
		return nil, err
	}

	info := &EIFInfo{}
	err = json.Unmarshal(res, info)
	if err != nil {
		return nil, err
	}

	return info, nil
}

func VerifyPCRs(pcrs map[string][]string, doc *attest.AttestationDoc) error {
	for key, values := range pcrs {
		pcrIndex, err := strconv.Atoi(key)
		if err != nil {
			return err
		}
		h := hex.EncodeToString(doc.PCRs[pcrIndex])

		found := false
		for _, pcr := range values {
			if pcr == h {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("PCR%d %s does not match %s", pcrIndex, h, values)
		}
	}
	return nil
}
