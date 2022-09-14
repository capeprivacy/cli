package pcrs

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	log "github.com/sirupsen/logrus"

	"github.com/capeprivacy/cli/attest"
)

type Measurements map[string]string

type EIFInfo struct {
	Measurements Measurements `json:"measurements"`
}

func DownloadEIF(bucket string, runtimeVersion string) (string, error) {
	sess := session.Must(session.NewSession())

	// Create a downloader with the session and default options
	downloader := s3manager.NewDownloader(sess)

	f, err := os.CreateTemp("", "runtime")
	if err != nil {
		return "", err
	}
	defer f.Close()

	key := fmt.Sprintf("runtime-%s.eif", runtimeVersion)
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

func SliceToMapStringSlice(slice []string) map[string][]string {
	m := make(map[string][]string)

	for _, val := range slice {
		spl := strings.Split(val, ":")
		pcrIndex := spl[0]
		pcrValue := spl[1]

		_, ok := m[pcrIndex]
		if !ok {
			m[pcrIndex] = make([]string, 0)
		}

		m[pcrIndex] = append(m[pcrIndex], pcrValue)
	}

	return m
}
