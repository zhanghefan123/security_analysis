package cmd

import (
	"fmt"
	"github.com/spf13/cobra"
)

// CreateVersionCmd 创建 Version 命令
func CreateVersionCmd() *cobra.Command {
	var versionCmd = &cobra.Command{
		Use:   "version",
		Short: "Return the version of ChainMaker",
		Long:  "Return the version of ChainMaker",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("version 1.0.0\n")
		},
	}
	return versionCmd
}
