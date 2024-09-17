package utils

import (
	"strings"
	"zhanghefan123/security/localconf"
)

func GetValidatorsFromLocalConfig() []string {
	seeds := localconf.ChainMakerConfig.NetConfig.Seeds
	validators := make([]string, len(seeds))
	for _, multiAddr := range seeds {
		differentParts := strings.Split(multiAddr, "/")
		lastPart := differentParts[len(differentParts)-1]
		validators = append(validators, lastPart)
	}
	return validators
}

func GetValidatorsMapFromLocalConfig() map[string]struct{} {
	seeds := localconf.ChainMakerConfig.NetConfig.Seeds
	validators := make(map[string]struct{})
	for _, multiAddr := range seeds {
		differentParts := strings.Split(multiAddr, "/")
		lastPart := differentParts[len(differentParts)-1]
		validators[lastPart] = struct{}{}
	}
	return validators
}
