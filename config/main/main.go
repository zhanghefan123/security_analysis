package main

import (
	"os"
	"zhanghefan123/security/config/main/cmd"
)

func main() {
	rootCmd := cmd.CreateRootCmd()
	generateCmd := cmd.CreateGenerateCmd()
	rootCmd.AddCommand(generateCmd)
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
