/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

// Package logger used to get a logger for modules to write log
package logger

import (
	"strings"
	"sync"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"zhanghefan123/security/common/log"
)

// Log module
const (
	MODULE_BLOCKCHAIN = "[Blockchain]"
	MODULE_NET        = "[Net]"
	MODULE_STORAGE    = "[Storage]"
	MODULE_SNAPSHOT   = "[Snapshot]"
	MODULE_CONSENSUS  = "[Consensus]"
	MODULE_TXPOOL     = "[TxPool]"
	MODULE_CORE       = "[Core]"
	MODULE_VM         = "[Vm]"
	MODULE_RPC        = "[Rpc]"
	MODULE_LEDGER     = "[Ledger]" //nolint:golint,unused
	MODULE_CLI        = "[Cli]"
	MODULE_CHAINCONF  = "[ChainConf]"
	MODULE_ACCESS     = "[Access]"
	MODULE_MONITOR    = "[Monitor]"
	MODULE_SYNC       = "[Sync]"
	MODULE_DPOS       = "[DPoS]"
	MODULE_TXFILTER   = "[TxFilter]"
	MODULE_RPC_SERVER = "[RPCServer]"

	MODULE_BRIEF = "[Brief]"
	MODULE_EVENT = "[Event]"

	DefaultStackTraceLevel = "ERROR"
)

var (
	// map[module-name]map[module-name+chainId]zap.AtomicLevel
	loggerLevels = make(map[string]map[string]zap.AtomicLevel)
	loggerMutex  sync.Mutex
	logConfig    *LogConfig

	// map[moduleName+chainId]*CMLogger
	cmLoggers = sync.Map{}
)

// CMLogger is an implementation of chainmaker logger.
type CMLogger struct {
	zlog        *zap.SugaredLogger
	name        string
	chainId     string
	lock        sync.RWMutex
	logLevel    log.LOG_LEVEL
	kafkaLogger *KafkaLogger
}

// Logger 获得CMLogger内部的zap Logger
// @return *zap.SugaredLogger
func (l *CMLogger) Logger() *zap.SugaredLogger {
	l.lock.RLock()
	defer l.lock.RUnlock()
	return l.zlog
}

// Debug Debug级日志
// @param args
func (l *CMLogger) Debug(args ...interface{}) {
	l.zlog.Debug(args...)
}

// Debugf Debug级日志，支持format
// @param format
// @param args
func (l *CMLogger) Debugf(format string, args ...interface{}) {
	l.zlog.Debugf(format, args...)
}

// Debugw Debug级日志，支持kv对
// @param msg
// @param keysAndValues
func (l *CMLogger) Debugw(msg string, keysAndValues ...interface{}) {
	l.zlog.Debugw(msg, keysAndValues...)
}

// Error Error级日志
// @param args
func (l *CMLogger) Error(args ...interface{}) {
	l.zlog.Error(args...)
}

// Errorf Error级日志，支持format
// @param format
// @param args
func (l *CMLogger) Errorf(format string, args ...interface{}) {
	l.zlog.Errorf(format, args...)
}

// Errorw Error级日志，支持kv对
// @param msg
// @param keysAndValues
func (l *CMLogger) Errorw(msg string, keysAndValues ...interface{}) {
	l.zlog.Errorw(msg, keysAndValues...)
}

// Fatal 失败日志
// @param args
func (l *CMLogger) Fatal(args ...interface{}) {
	l.zlog.Fatal(args...)
}

// Fatalf 失败日志，带Format
// @param format
// @param args
func (l *CMLogger) Fatalf(format string, args ...interface{}) {
	l.zlog.Fatalf(format, args...)
}

// Fatalw 失败日志，支持KV
// @param msg
// @param keysAndValues
func (l *CMLogger) Fatalw(msg string, keysAndValues ...interface{}) {
	l.zlog.Fatalw(msg, keysAndValues...)
}

// Info Info级日志
// @param args
func (l *CMLogger) Info(args ...interface{}) {
	l.zlog.Info(args...)
}

// Infof Info级日志，支持Format
// @param format
// @param args
func (l *CMLogger) Infof(format string, args ...interface{}) {
	l.zlog.Infof(format, args...)
}

// Infow Info级日志，支持kv对
// @param msg
// @param keysAndValues
func (l *CMLogger) Infow(msg string, keysAndValues ...interface{}) {
	l.zlog.Infow(msg, keysAndValues...)
}

// Panic 记录日志并抛出Panic
// @param args
func (l *CMLogger) Panic(args ...interface{}) {
	l.zlog.Panic(args...)
}

// Panicf 记录日志并抛出Panic，日志支持format
// @param format
// @param args
func (l *CMLogger) Panicf(format string, args ...interface{}) {
	l.zlog.Panicf(format, args...)
}

// Panicw 记录日志并抛出Panic，日志支持kv对
// @param msg
// @param keysAndValues
func (l *CMLogger) Panicw(msg string, keysAndValues ...interface{}) {
	l.zlog.Panicw(msg, keysAndValues...)
}

// Warn Warn级日志
// @param args
func (l *CMLogger) Warn(args ...interface{}) {
	l.zlog.Warn(args...)
}

// Warnf Warn级日志，支持format
// @param format
// @param args
func (l *CMLogger) Warnf(format string, args ...interface{}) {
	l.zlog.Warnf(format, args...)
}

// Warnw Warn级日志，支持kv对
// @param msg
// @param keysAndValues
func (l *CMLogger) Warnw(msg string, keysAndValues ...interface{}) {
	l.zlog.Warnw(msg, keysAndValues...)
}

// DebugDynamic 动态Debug级日志，只有需要日志输出时才会运行匿名函数的内容，产生日志结果
// @param getStr
func (l *CMLogger) DebugDynamic(getStr func() string) {
	if l.logLevel == log.LEVEL_DEBUG {
		str := getStr()
		l.zlog.Debug(str)
	}
}

// InfoDynamic 动态Info级日志，只有需要日志输出时才会运行匿名函数的内容，产生日志结果
// @param getStr
func (l *CMLogger) InfoDynamic(getStr func() string) {
	if l.logLevel == log.LEVEL_DEBUG || l.logLevel == log.LEVEL_INFO {
		l.zlog.Info(getStr())
	}
}

// SetLogger set logger.
func (l *CMLogger) SetLogger(logger *zap.SugaredLogger) {
	l.lock.Lock()
	defer l.lock.Unlock()
	l.zlog = logger
}

//Close sync log and close handler
func (l *CMLogger) Close() {
	l.zlog.Sync() //nolint
	if l.kafkaLogger != nil {
		l.kafkaLogger.Producer.Close()
	}
}

// newCMLogger create a new CMLogger.
func newCMLogger(name string, chainId string, logger *zap.SugaredLogger, logLevel log.LOG_LEVEL,
	kl *KafkaLogger) *CMLogger {
	return &CMLogger{name: name, chainId: chainId, zlog: logger, logLevel: logLevel, kafkaLogger: kl}
}

// SetLogConfig set the config of logger module, called in initialization of config module
func SetLogConfig(config *LogConfig) {
	logConfig = config
	RefreshLogConfig(logConfig)
}

// GetLogger find or create a CMLogger with module name, usually called in initialization of all module.
// After one module get the logger, the module can use it forever until the program terminate.
func GetLogger(name string) *CMLogger {
	return GetLoggerByChain(name, "")
}

// GetLoggerByChain find the CMLogger object with module name and chainId,
// usually called in initialization of all module.
// One module can get a logger for each chain, then logger can be use forever until the program terminate.
func GetLoggerByChain(name, chainId string) *CMLogger {
	logHeader := name + chainId
	var logger *CMLogger
	loggerVal, ok := cmLoggers.Load(logHeader)
	if ok {
		logger, _ = loggerVal.(*CMLogger)
		return logger
	}
	zapLogger, logLevel, kafkaLogger := createLoggerByChain(name, chainId)

	logger = newCMLogger(name, chainId, zapLogger, logLevel, kafkaLogger)
	loggerVal, ok = cmLoggers.LoadOrStore(logHeader, logger)
	if ok {
		logger, _ = loggerVal.(*CMLogger)
	}
	return logger

}

func createLoggerByChain(name, chainId string) (*zap.SugaredLogger, log.LOG_LEVEL, *KafkaLogger) {
	var config log.LogConfig
	var pureName string

	if logConfig == nil {
		logConfig = DefaultLogConfig()
	}
	var kLogConfig *KafkaLogConfig
	if logConfig.SystemLog.LogLevelDefault == "" {
		//默认日志
		defaultLogNode := GetDefaultLogNodeConfig()
		config = log.LogConfig{
			Module:          "[DEFAULT]",
			ChainId:         chainId,
			LogPath:         defaultLogNode.GetFilePath(chainId),
			LogLevel:        log.GetLogLevel(defaultLogNode.LogLevelDefault),
			MaxAge:          defaultLogNode.MaxAge,
			RotationTime:    defaultLogNode.RotationTime,
			JsonFormat:      defaultLogNode.JsonFormat,
			ShowLine:        true,
			LogInConsole:    defaultLogNode.LogInConsole,
			ShowColor:       defaultLogNode.ShowColor,
			IsBrief:         false,
			StackTraceLevel: defaultLogNode.StackTraceLevel,
		}
	} else {
		if name == MODULE_BRIEF {
			//Brief的日志
			config = log.LogConfig{
				Module:          name,
				ChainId:         chainId,
				LogPath:         logConfig.BriefLog.GetFilePath(chainId),
				LogLevel:        log.GetLogLevel(logConfig.BriefLog.LogLevelDefault),
				MaxAge:          logConfig.BriefLog.MaxAge,
				RotationTime:    logConfig.BriefLog.RotationTime,
				RotationSize:    logConfig.BriefLog.RotationSize,
				JsonFormat:      logConfig.BriefLog.JsonFormat,
				ShowLine:        true,
				LogInConsole:    logConfig.BriefLog.LogInConsole,
				ShowColor:       logConfig.BriefLog.ShowColor,
				IsBrief:         true,
				StackTraceLevel: logConfig.BriefLog.StackTraceLevel,
			}
			kLogConfig = logConfig.BriefLog.Kafka
		} else if name == MODULE_EVENT {
			//Event的日志
			config = log.LogConfig{
				Module:          name,
				ChainId:         chainId,
				LogPath:         logConfig.EventLog.GetFilePath(chainId),
				LogLevel:        log.GetLogLevel(logConfig.EventLog.LogLevelDefault),
				MaxAge:          logConfig.EventLog.MaxAge,
				RotationTime:    logConfig.EventLog.RotationTime,
				RotationSize:    logConfig.EventLog.RotationSize,
				JsonFormat:      logConfig.EventLog.JsonFormat,
				ShowLine:        true,
				LogInConsole:    logConfig.EventLog.LogInConsole,
				ShowColor:       logConfig.EventLog.ShowColor,
				IsBrief:         false,
				StackTraceLevel: logConfig.EventLog.StackTraceLevel,
			}
			kLogConfig = logConfig.EventLog.Kafka
		} else {
			//模块对应的日志
			pureName = strings.ToLower(strings.Trim(name, "[]"))
			myconfig := logConfig.GetConfigByModuleName(pureName)
			value, exists := logConfig.SystemLog.LogLevels[pureName]
			if !exists {
				value = myconfig.LogLevelDefault
			}
			config = log.LogConfig{
				Module:          name,
				ChainId:         chainId,
				LogPath:         myconfig.GetFilePath(chainId),
				LogLevel:        log.GetLogLevel(value),
				MaxAge:          myconfig.MaxAge,
				RotationTime:    myconfig.RotationTime,
				RotationSize:    myconfig.RotationSize,
				JsonFormat:      myconfig.JsonFormat,
				ShowLine:        true,
				LogInConsole:    myconfig.LogInConsole,
				ShowColor:       myconfig.ShowColor,
				IsBrief:         false,
				StackTraceLevel: myconfig.StackTraceLevel,
			}
			kLogConfig = myconfig.Kafka
		}
	}
	//如果配置中指定了该模块的日志配置，则使用指定的配置

	var logger *zap.SugaredLogger
	var level zap.AtomicLevel
	var kafkaLogger *KafkaLogger
	var err error
	if kLogConfig != nil {
		kafkaLogger, err = NewKafkaProducer(kLogConfig, chainId)
		if err != nil {
			panic("init kafka producer fail. " + err.Error())
		}

		logger, level = log.InitSugarLogger(&config, kafkaLogger)
	} else {
		logger, level = log.InitSugarLogger(&config)
	}
	if pureName != "" {
		if _, exist := loggerLevels[pureName]; !exist {
			loggerLevels[pureName] = make(map[string]zap.AtomicLevel)
		}
		logHeader := name + chainId
		loggerLevels[pureName][logHeader] = level
	}
	return logger, config.LogLevel, kafkaLogger
}

func refreshAllLoggerOfCmLoggers() {
	cmLoggers.Range(func(_, value interface{}) bool {
		cmLogger, _ := value.(*CMLogger)
		newLogger, logLevel, kl := createLoggerByChain(cmLogger.name, cmLogger.chainId)
		cmLogger.SetLogger(newLogger)
		cmLogger.logLevel = logLevel
		cmLogger.kafkaLogger = kl
		return true
	})
}

// RefreshLogConfig refresh log levels of modules at initiation time of log module
// or refresh log levels of modules dynamically at running time.
func RefreshLogConfig(config *LogConfig) {
	loggerMutex.Lock()
	defer loggerMutex.Unlock()
	// scan loggerLevels and find the level from config, if can't find level, set it to default
	for name, loggers := range loggerLevels {
		var logLevevl zapcore.Level
		var strlevel string
		var exist bool
		if strlevel, exist = config.SystemLog.LogLevels[name]; !exist {
			strlevel = config.SystemLog.LogLevelDefault
		}
		switch log.GetLogLevel(strlevel) {
		case log.LEVEL_DEBUG:
			logLevevl = zap.DebugLevel
		case log.LEVEL_INFO:
			logLevevl = zap.InfoLevel
		case log.LEVEL_WARN:
			logLevevl = zap.WarnLevel
		case log.LEVEL_ERROR:
			logLevevl = zap.ErrorLevel
		default:
			logLevevl = zap.InfoLevel
		}
		for _, aLevel := range loggers {
			aLevel.SetLevel(logLevevl)
		}
	}

	refreshAllLoggerOfCmLoggers()
}

// DefaultLogConfig create default config for log module
func DefaultLogConfig() *LogConfig {
	defaultLogNode := GetDefaultLogNodeConfig()
	config := &LogConfig{
		SystemLog: LogNodeConfig{
			LogLevelDefault: defaultLogNode.LogLevelDefault,
			FilePath:        defaultLogNode.FilePath,
			MaxAge:          defaultLogNode.MaxAge,
			RotationTime:    defaultLogNode.RotationTime,
			RotationSize:    defaultLogNode.RotationSize,
			LogInConsole:    defaultLogNode.LogInConsole,
			StackTraceLevel: defaultLogNode.StackTraceLevel,
		},
		BriefLog: LogNodeConfig{
			LogLevelDefault: defaultLogNode.LogLevelDefault,
			FilePath:        defaultLogNode.FilePath,
			MaxAge:          defaultLogNode.MaxAge,
			RotationTime:    defaultLogNode.RotationTime,
			RotationSize:    defaultLogNode.RotationSize,
			LogInConsole:    defaultLogNode.LogInConsole,
			StackTraceLevel: defaultLogNode.StackTraceLevel,
		},
		EventLog: LogNodeConfig{
			LogLevelDefault: defaultLogNode.LogLevelDefault,
			FilePath:        defaultLogNode.FilePath,
			MaxAge:          defaultLogNode.MaxAge,
			RotationTime:    defaultLogNode.RotationTime,
			RotationSize:    defaultLogNode.RotationSize,
			LogInConsole:    defaultLogNode.LogInConsole,
			StackTraceLevel: defaultLogNode.StackTraceLevel,
		},
	}
	return config
}

// GetDefaultLogNodeConfig create a default log config of node
func GetDefaultLogNodeConfig() LogNodeConfig {
	return LogNodeConfig{
		LogLevelDefault: log.DEBUG,
		FilePath:        "./default.log",
		MaxAge:          log.DEFAULT_MAX_AGE,
		RotationTime:    log.DEFAULT_ROTATION_TIME,
		RotationSize:    log.DEFAULT_ROTATION_SIZE,
		LogInConsole:    true,
		ShowColor:       true,
		StackTraceLevel: DefaultStackTraceLevel,
	}
}
