package cmd

import (
	"fmt"
	"path"
	"strings"

	"github.com/capeprivacy/cli/pcrs"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

// runCmd represents the get-prcs command
var getPCRsCmd = &cobra.Command{
	Use:   "get-pcrs",
	Short: "returns the pcrs of a given sentinel version",
	Long:  "",
	RunE:  getPCRs,
}

func init() {
	rootCmd.AddCommand(getPCRsCmd)

	getPCRsCmd.PersistentFlags().String("version", "release-8436e50", "the version of the sentinel EIF to get PCRs for")
	getPCRsCmd.PersistentFlags().StringP("bucket", "b", "eif-release-builds-demo", "the artifact source bucket in S3")
}

func getPCRs(cmd *cobra.Command, args []string) error {
	version, err := cmd.Flags().GetString("version")
	if err != nil {
		return fmt.Errorf("error retrieving version flag %s", err)
	}

	bucket, err := cmd.Flags().GetString("bucket")
	if err != nil {
		return fmt.Errorf("error retrieving bucket flag %s", err)
	}

	p, err := pcrs.DownloadEIF(bucket, version)
	if err != nil {
		return err
	}

	info, err := pcrs.GetEIFInfo(path.Base(p))
	if err != nil {
		return err
	}

	for key, item := range info.Measurements {
		if strings.HasPrefix(key, "PCR") {
			log.Infof("%s:\t%s", key, item)
		}
	}
	return nil
}
