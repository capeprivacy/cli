/*
Copyright © 2022 NAME HERE <EMAIL ADDRESS>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
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
		return
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
