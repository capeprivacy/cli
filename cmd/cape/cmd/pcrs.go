package cmd

import (
	"fmt"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/pcrs"
)

// runCmd represents the get-prcs command
var getPCRsCmd = &cobra.Command{
	Use:   "get-pcrs",
	Short: "Retrieve the PCRs of a given runtime version",
	Long:  `Retrieve the PCRs of a given runtime version.

The PCRs are measurements of the executable version of the cape
runtime that processes requests. These PCRs can be supplied to
other commands to validate that Cape is running a version of the
code that you've verified.`,
	RunE:  getPCRs,
}

func init() {
	rootCmd.AddCommand(getPCRsCmd)

	getPCRsCmd.PersistentFlags().String("version", "release-434bd34", "the version of the runtime EIF to get PCRs for")
	getPCRsCmd.PersistentFlags().StringP("bucket", "b", "user-eif-release-bucket", "the artifact source bucket in S3")
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
