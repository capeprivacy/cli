package cmd

import (
	"fmt"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show cape version",
	Run: func(cmd *cobra.Command, args []string) {
		if version != "unknown" {
			fmt.Println(version)
			return
		}

		if bi, ok := debug.ReadBuildInfo(); ok {
			var vcs struct {
				sys string
				rev string
			}
			for _, setting := range bi.Settings {
				switch setting.Key {
				case "vcs":
					vcs.sys = setting.Value
				case "vcs.revision":
					vcs.rev = fmt.Sprintf("%.7s", setting.Value)
				case "vcs.modified":
					if setting.Value == "true" {
						vcs.rev = fmt.Sprintf("%s-dirty", vcs.rev)
					}
				}
			}
			if vcs.sys != "" {
				fmt.Printf("%s vcs: %s:%s\n", bi.Main.Version, vcs.sys, vcs.rev)
			} else {
				fmt.Println(bi.Main.Version)
			}
			return
		}

		fmt.Println("unknown")
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
