package generator

import (
	"sync"
	"zhanghefan123/security/config/main/vars"
)

func Generate(configParams *vars.ConfigParams) {
	wg := sync.WaitGroup{}
	wg.Add(configParams.NodeNumber)
	for index := 0; index < configParams.NodeNumber; index++ {
		go func(nodeIndex int) {
			defer wg.Done()
			GenerateDir(nodeIndex, configParams.GeneratedDestination)
			GenerateSecretKey(nodeIndex, configParams.GeneratedDestination)
		}(index)
	}
	wg.Wait()
}
