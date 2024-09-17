package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"zhanghefan123/security/localconf"
)

func InitFlagSet() *pflag.FlagSet {
	flags := &pflag.FlagSet{}
	flags.StringVarP(&localconf.ConfigFilepath,
		flagNameOfConfigFilePath,
		flagNameShortHandOfConfigFilePath,
		localconf.ConfigFilepath,
		"specify config file path, if not set, default use ./chainmaker.yml")
	return flags
}

func AttachFlags(cmd *cobra.Command, flagNames []string) {
	initializedFlags := InitFlagSet()
	cmdFlags := cmd.Flags()
	for _, flagName := range flagNames {
		if flag := initializedFlags.Lookup(flagName); flag != nil {
			cmdFlags.AddFlag(flag)
			_ = cmd.MarkFlagRequired(flagName)
		}
	}
}
