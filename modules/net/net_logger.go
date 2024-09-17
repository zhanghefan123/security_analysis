/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package net

import (
	"zhanghefan123/security/protocol"
)

var GlobalNetLogger protocol.Logger

func init() {
	//GlobalNetLogger = logger.GetLogger(logger.MODULE_NET)
	//liquid.InitLogger(GlobalNetLogger, func(chainId string) protocol.Logger {
	//	return logger.GetLoggerByChain(logger.MODULE_NET, chainId)
	//})
}
