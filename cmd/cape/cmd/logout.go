package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Logout of Cape",
	RunE:  logout,
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}

func logout(cmd *cobra.Command, args []string) error {
	authFile := filepath.Join(C.LocalConfigDir, C.LocalAuthFileName)

	if err := os.Remove(authFile); err != nil {
		fmt.Println(err)
	} else {
		fmt.Println("You are now logged out. To login again type: cape login")
	}

	return nil
}
