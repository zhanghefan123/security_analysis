package cmd

import "github.com/spf13/cobra"

// CreateRootCmd 创建根命令
func CreateRootCmd() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   "main",
		Short: "Chain config generation",
		Long:  "Chain config generation",
	}
	return rootCmd
}
