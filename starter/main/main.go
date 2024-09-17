/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package main

import (
	"os"
	"zhanghefan123/security/starter/main/cmd"
)

func main() {
	rootCmd := cmd.CreateRootCmd()
	startCmd := cmd.CreateStartCmd()
	versionCmd := cmd.CreateVersionCmd()
	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(versionCmd)
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
