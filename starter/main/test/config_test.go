package test

import (
	"fmt"
	"github.com/spf13/cobra"
	"testing"
	"zhanghefan123/security/localconf"
	"zhanghefan123/security/starter/main/cmd"
)

// TestInitConfig 进行配置文件的测试
func TestInitConfig(t *testing.T) {
	localconf.ConfigFilepath = "./config/node1/chainmaker.yml"
	cmd.InitLocalConfig(&cobra.Command{})
	for _, item := range localconf.ChainMakerConfig.BlockChainConfig {
		fmt.Printf("chainId: %s genesis block path: %s\n", item.ChainId, item.Genesis)
	}
	fmt.Printf("RequestChannelSize: %d", localconf.ChainMakerConfig.RpcConfig.RequestChannelSize)
}
