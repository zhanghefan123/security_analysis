package cmd

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"zhanghefan123/security/config/main/vars"
)

func InitFlagSet() *pflag.FlagSet {
	flags := &pflag.FlagSet{}
	flags.IntVarP(&vars.ConfigParamsInstance.NodeNumber,
		vars.FlagNameOfNodeNumber,
		vars.FlagNameShortHandOfNodeNumber,
		vars.ConfigParamsInstance.NodeNumber,
		"specify the node number",
	)
	flags.IntVarP(&vars.ConfigParamsInstance.StartP2PPort,
		vars.FlagNameOfStartP2PPort,
		vars.FlagNameShortHandOfStartP2PPort,
		vars.ConfigParamsInstance.StartP2PPort,
		"specify the start p2p port")
	flags.IntVarP(&vars.ConfigParamsInstance.StartRpcPort,
		vars.FlagNameOfStartRPCPort,
		vars.FlagNameShortHandOfStartRPCPort,
		vars.ConfigParamsInstance.StartRpcPort,
		"Specify the start rpc port")
	flags.IntVarP(&vars.ConfigParamsInstance.ConsensusType,
		vars.FlagNameOfChooseConsensusType,
		vars.FlagNameShortHandOfChooseConsensusType,
		vars.ConfigParamsInstance.ConsensusType,
		"specify the consensus type")
	flags.StringVarP(&vars.ConfigParamsInstance.GeneratedDestination,
		vars.FlagNameOfGeneratedDestination,
		vars.FlagNameShortHandOfGeneratedDestination,
		vars.ConfigParamsInstance.GeneratedDestination,
		"specify the generated destination")
	return flags
}

func AttachFlags(cmd *cobra.Command, FlagNameS []string) {
	initializedFlags := InitFlagSet()
	cmdFlags := cmd.Flags()
	for _, flagName := range FlagNameS {
		if flag := initializedFlags.Lookup(flagName); flag != nil {
			cmdFlags.AddFlag(flag)
			_ = cmd.MarkFlagRequired(flagName)
		}
	}
}
