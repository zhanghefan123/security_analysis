/*
Copyright (C) BABEC. All rights reserved.
Copyright (C) THL A29 Limited, a Tencent company. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package monitor

import (
	"fmt"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "chainmaker"
)

const (
	SUBSYSTEM_GRPC                    = "grpc"
	SUBSYSTEM_CORE_COMMITTER          = "committer"
	SUBSYSTEM_RPCSERVER               = "rpcserver"
	SUBSYSTEM_CORE_PROPOSER_SCHEDULER = "scheduler"
	SUBSYSTEM_CORE_PROPOSER           = "proposer"
	SUBSYSTEM_CORE_VERIFIER           = "verifier"
	SUBSYSTEM_WASM_WASMER             = "wasmer"
	SUBSYSTEM_TXPOOL                  = "txpool"
	SUBSYSTEM_VM                      = "vm"

	ChainId                           = "chainId"
	PoolType                          = "poolType"
	MetricBlockSize                   = "metric_block_size"
	MetricBlockCounter                = "metric_block_counter"
	MetricTxCounter                   = "metric_tx_counter"
	MetricTxPoolSize                  = "metric_tx_pool_size"       // tx pool
	MetricValidateTxInDBTime          = "validate_tx_exist_db_time" // tx pool
	MetricValidateTxSignTime          = "validate_tx_sign_time"     // tx pool
	MetricTpsGauge                    = "metric_tps_gauge"
	MetricBlockCommitTime             = "metric_block_commit_time"
	MetricBlockIntervalTime           = "metric_block_interval_time"
	HelpCurrentBlockSizeMetric        = "current block size metric"
	HelpBlockCountsMetric             = "block counts metric"
	HelpTxCountsMetric                = "tx counts metric"
	HelpTxPoolSizeMetric              = "tx pool size metric"                 // tx pool
	MetricValidateTxInDBTimeMetric    = "validate tx exist in db time metric" // tx pool
	MetricValidateTxSignTimeMetric    = "validate tx sign time metric"        // tx pool
	HelpTpsGaugeMetric                = "real-time transaction per second (TPS) metric"
	HelpBlockCommitTimeMetric         = "block commit time metric"
	HelpBlockIntervalTimeMetric       = "block interval metric"
	MetricDeployedContractCounter     = "metric_deployed_contract_counter"
	MetricContractInvokeCounter       = "metric_contract_invoke_counter"
	MetricGasUsedHistogram            = "metric_gas_used_histogram"
	HelpDeployedContractCounterMetric = "deployed contract counter metric"
	HelpContractInvokeCounterMetric   = "contract invoke counter metric"
	HelpGasUsedHistogramMetric        = "gas used histogram metric"
)

var (
	counterVecs        map[string]*prometheus.CounterVec
	histogramVecs      map[string]*prometheus.HistogramVec
	gaugeVecs          map[string]*prometheus.GaugeVec
	counterVecsMutex   sync.Mutex
	histogramVecsMutex sync.Mutex
	gaugeVecsMutex     sync.Mutex
)

func init() {
	counterVecs = make(map[string]*prometheus.CounterVec)
	histogramVecs = make(map[string]*prometheus.HistogramVec)
	gaugeVecs = make(map[string]*prometheus.GaugeVec)
}

func NewCounterVec(subsystem, name, help string, labels ...string) *prometheus.CounterVec {
	counterVecsMutex.Lock()
	defer counterVecsMutex.Unlock()
	s := fmt.Sprintf("%s_%s", subsystem, name)
	if metric, ok := counterVecs[s]; ok {
		return metric
	}
	metric := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      name,
			Help:      help,
		}, labels)
	prometheus.MustRegister(metric)
	counterVecs[s] = metric
	return metric
}

func NewHistogramVec(subsystem, name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
	histogramVecsMutex.Lock()
	defer histogramVecsMutex.Unlock()
	s := fmt.Sprintf("%s_%s", subsystem, name)
	if metric, ok := histogramVecs[s]; ok {
		return metric
	}
	metric := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      name,
			Help:      help,
			Buckets:   buckets,
		}, labels)
	prometheus.MustRegister(metric)
	histogramVecs[s] = metric
	return metric
}

func NewGaugeVec(subsystem, name, help string, labels ...string) *prometheus.GaugeVec {
	gaugeVecsMutex.Lock()
	defer gaugeVecsMutex.Unlock()
	s := fmt.Sprintf("%s_%s", subsystem, name)
	if metric, ok := gaugeVecs[s]; ok {
		return metric
	}
	metric := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      name,
			Help:      help,
		}, labels)
	prometheus.MustRegister(metric)
	gaugeVecs[s] = metric
	return metric
}

func NewHistogram(subsystem, name, help string, buckets []float64) *prometheus.Histogram {
	metric := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      name,
			Help:      help,
			Buckets:   buckets,
		})

	prometheus.MustRegister(metric)
	return &metric
}

//func MetricCounterInc(metric *prometheus.CounterVec, lvs ...string) {
//	if localconf.ChainMakerConfig.MonitorConfig.Enabled {
//		metric.WithLabelValues(lvs...).Inc()
//	}
//}
