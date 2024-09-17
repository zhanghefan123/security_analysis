package cmd

import (
	"fmt"
	"github.com/kr/pretty"
	"github.com/spf13/cobra"
	"zhanghefan123/security/config/main/generator"
	"zhanghefan123/security/config/main/vars"
)

func CreateGenerateCmd() *cobra.Command {
	var generateCmd = &cobra.Command{
		Use:   "generate",
		Short: "generate configuration",
		Long:  "generate configuration",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("generate configuration")
			pretty.Println(*(vars.ConfigParamsInstance))
			generator.Generate(vars.ConfigParamsInstance)
		},
	}
	AttachFlags(generateCmd, []string{vars.FlagNameOfNodeNumber, vars.FlagNameOfStartP2PPort,
		vars.FlagNameOfStartRPCPort, vars.FlagNameOfChooseConsensusType,
		vars.FlagNameOfGeneratedDestination})
	return generateCmd
}
