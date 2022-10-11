package cmd

import (
	dep "github.com/capeprivacy/cli/ui/deploy"
)

import "github.com/spf13/cobra"

var deploy2Cmd = &cobra.Command{
	Use:   "deploy2 directory | zip_file",
	Short: "Deploy a function",
	Long: `Deploy a function to Cape.

This will return an ID that can later be used to invoke the deployed function
with cape run (see cape run -h for details).	
`,

	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := getAuthToken()
		if err != nil {
			return err
		}

		C.AuthToken = token
		return dep.NewProgram(&C, args[0]).Start()
	},
}

func init() {
	rootCmd.AddCommand(deploy2Cmd)
}
