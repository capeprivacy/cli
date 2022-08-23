package cmd

import (
	"github.com/spf13/cobra"
)

var signupCmd = &cobra.Command{
	Use:   "signup",
	Short: "Signup to Cape",
	RunE:  login,
}

func init() {
	rootCmd.AddCommand(signupCmd)
}
