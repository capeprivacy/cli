package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var functionCmd = &cobra.Command{
	Use:   "function",
	Short: "Utilities for working with functions",
}

var functionCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Creates the boilerplate code for a function",
	RunE: func(cmd *cobra.Command, args []string) error {
		err := create(cmd, args)
		_, ok := err.(UserError)
		// Print usage on UserError, suppress for success and internal errors
		cmd.SilenceUsage = !ok
		return err
	},
}

func init() {
	rootCmd.AddCommand(functionCmd)

	functionCmd.AddCommand(functionCreateCmd)

	functionCreateCmd.PersistentFlags().StringP("location", "l", ".", "location to create the function")
}

var appContents = `def cape_handler(n):
    data = n.decode("utf-8")
    return data
`

var requirementsContents = `# Put any requirements here`

func create(cmd *cobra.Command, args []string) error {
	if len(args) != 1 {
		return UserError{Msg: "you must pass a function name", Err: fmt.Errorf("invalid number of input arguments")}
	}

	location, err := cmd.Flags().GetString("location")
	if err != nil {
		return UserError{Msg: "error retrieving location flag", Err: err}
	}

	name := args[0]

	if location != "" {
		name = filepath.Join(location, name)
	}

	err = os.Mkdir(name, 0755)
	if err != nil {
		return UserError{Msg: "unable to create function directory", Err: err}
	}

	appF, err := os.Create(filepath.Join(name, "app.py"))
	if err != nil {
		return UserError{Msg: "unable to create app.py file", Err: err}
	}
	defer appF.Close()

	_, err = appF.Write([]byte(appContents))
	if err != nil {
		return UserError{Msg: "unable to write to app.py", Err: err}
	}

	reqF, err := os.Create(filepath.Join(name, "requirements.txt"))
	if err != nil {
		return UserError{Msg: "unable to create requirements.txt file", Err: err}
	}
	defer reqF.Close()

	_, err = reqF.Write([]byte(requirementsContents))
	if err != nil {
		return UserError{Msg: "unable to write to requirements.txt", Err: err}
	}

	return nil
}
