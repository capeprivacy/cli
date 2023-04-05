package cmd

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/capeprivacy/cli/render"
	"github.com/capeprivacy/cli/sdk"
)

type DeployResponse struct {
	ID string `json:"id"`
}

// deployCmd represents the request command
var deployCmd = &cobra.Command{
	Use:   "deploy { <directory> | <zip_file> }",
	Short: "Deploy a function",
	Long: `Deploy a function to Cape.

This will return an ID that can later be used to invoke the deployed function
with cape run (see cape run -h for details).
`,

	RunE: func(cmd *cobra.Command, args []string) error {
		err := deploy(cmd, args)
		if _, ok := err.(UserError); !ok {
			cmd.SilenceUsage = true
		}
		return err
	},
}

func init() {
	rootCmd.AddCommand(deployCmd)

	deployCmd.PersistentFlags().StringP("token", "t", "", "authorization token to use")
	deployCmd.PersistentFlags().StringP("name", "n", "", "a name to give this function (default is the directory name)")
	deployCmd.PersistentFlags().StringSliceP("pcr", "p", []string{""}, "pass multiple PCRs to validate against")
	deployCmd.PersistentFlags().BoolP("public", "", false, "make the function public (anyone can run it)")

	registerTemplate(deployCmd.Name(), deployTmpl)
}

func deploy(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return UserError{Msg: "you must specify a directory to upload", Err: fmt.Errorf("invalid number of input arguments")}
	}

	u := C.EnclaveHost
	insecure := C.Insecure

	n, err := cmd.Flags().GetString("name")
	if err != nil {
		return UserError{Msg: "name not specified correctly", Err: err}
	}

	pcrSlice, err := cmd.Flags().GetStringSlice("pcr")
	if err != nil {
		return UserError{Msg: "error retrieving pcr flags", Err: err}
	}

	public, err := cmd.Flags().GetBool("public")
	if err != nil {
		return UserError{Msg: "error retrieving public flag", Err: err}
	}

	functionInput := args[0]
	name := getName(functionInput, n)

	token, _ := cmd.Flags().GetString("token")
	if token == "" {
		t, err := getAuthToken()
		if err != nil {
			return err
		}

		token = t
	}

	dID, checksum, err := doDeploy(u, token, functionInput, name, insecure, pcrSlice, public)
	if err != nil {
		return err
	}

	username, err := getUsername(token)
	if err != nil {
		return err
	}

	// older tokens might not have a username, in that case, we just won't tell them the function alias
	functionName := ""
	if username != "" {
		functionName = fmt.Sprintf("%s/%s", username, name)
	}

	output := struct {
		ID           string `json:"function_id"`
		Checksum     string `json:"function_checksum"`
		FunctionName string `json:"function_name,omitempty"`
	}{
		ID:           dID,
		Checksum:     fmt.Sprintf("%x", checksum),
		FunctionName: functionName,
	}

	return render.Ctx(cmd.Context()).Render(cmd.OutOrStdout(), output)
}

func getName(functionInput string, nameFlag string) string {
	if nameFlag != "" {
		return nameFlag
	}
	return strings.Split(filepath.Base(functionInput), ".")[0]
}

func doDeploy(url string, token string, functionInput string, functionName string, insecure bool, pcrSlice []string, public bool) (string, []byte, error) {
	reader, err := sdk.ProcessUserFunction(functionInput)
	if err != nil {
		return "", nil, err
	}

	keyReq, err := GetKeyRequest(pcrSlice, token)
	if err != nil {
		return "", nil, err
	}

	id, checksum, err := sdk.Deploy(sdk.DeployRequest{
		URL:       url,
		Name:      functionName,
		Reader:    reader,
		Insecure:  insecure,
		PcrSlice:  pcrSlice,
		Public:    public,
		AuthToken: token,
	}, keyReq)
	if err != nil {
		return "", nil, fmt.Errorf("unable to deploy function: %w", err)
	}

	return id, checksum, nil
}

func getUsername(t string) (string, error) {
	token, err := jwt.Parse([]byte(t), jwt.WithVerify(false))
	if err != nil {
		return "", err
	}

	return token.PrivateClaims()["https://capeprivacy.com/username"].(string), nil
}

func getAuthToken() (string, error) {
	tokenResponse, err := getTokenResponse()
	if err != nil {
		return "", fmt.Errorf("failed to get auth token (did you run 'cape login'?): %v", err)
	}

	if tokenResponse.AccessToken == "" {
		return "", fmt.Errorf("empty access token (did you run 'cape login'?)")
	}

	log.Debug("* Retrieved Auth Token")

	return tokenResponse.AccessToken, nil
}

var deployTmpl = `Function ID       ➜  {{ .ID }}
Function Checksum ➜  {{ .Checksum }}
Function Name     ➜  {{ .FunctionName }}
`
