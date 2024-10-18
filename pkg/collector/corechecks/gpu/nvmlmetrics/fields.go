// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux

package nvmlmetrics

import (
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/hashicorp/go-multierror"
)

const fieldsMetricsCollectorName = "fields"

type fieldsMetricsCollector struct {
	device nvml.Device
	tags   []string
}

func newFieldsMetricsCollector(_ nvml.Interface, device nvml.Device, tags []string) (Collector, error) {
	return &fieldsMetricsCollector{
		device: device,
		tags:   tags,
	}, nil
}

// Collect collects all the metrics from the given NVML device.
func (coll *fieldsMetricsCollector) Collect() ([]Metric, error) {
	var err error

	vals := make([]nvml.FieldValue, 0, len(allfieldValueMetrics))

	for i, metric := range allfieldValueMetrics {
		vals[i].FieldId = metric.fieldValueID
	}

	ret := coll.device.GetFieldValues(vals)
	metrics := make([]Metric, 0, len(allfieldValueMetrics))
	for i, val := range vals {
		name := allfieldValueMetrics[i].name
		if val.NvmlReturn != uint32(nvml.SUCCESS) {
			err = multierror.Append(err, fmt.Errorf("failed to get field value %s: %s", name, nvml.ErrorString(nvml.Return(val.NvmlReturn))))
			continue
		}

		value, convErr := metricValueToDouble(val)
		if convErr != nil {
			err = multierror.Append(err, fmt.Errorf("failed to convert field value %s: %w", name, convErr))
		}

		metrics = append(metrics, Metric{Name: name, Value: value, Tags: coll.tags})
	}

	return metrics, ret
}

// Close cleans up any resources used by the collector (no-op for this collector).
func (coll *fieldsMetricsCollector) Close() error {
	return nil
}

// Name returns the name of the collector.
func (coll *fieldsMetricsCollector) Name() string {
	return fieldsMetricsCollectorName
}

// fieldValueMetric represents a metric that can be retrieved using the NVML
// FieldValues API, and associates a name for that metric
type fieldValueMetric struct {
	name         string
	fieldValueID uint32 // No specific type, but these are constants prefixed with FI_DEV in the nvml package
}

var allfieldValueMetrics = []fieldValueMetric{
	{"memory.temperature", nvml.FI_DEV_MEMORY_TEMP},
	{"nvlink.bandwidth.c0", nvml.FI_DEV_NVLINK_BANDWIDTH_C0_TOTAL},
	{"nvlink.bandwidth.c1", nvml.FI_DEV_NVLINK_BANDWIDTH_C1_TOTAL},
	{"pci.replay_counter", nvml.FI_DEV_PCIE_REPLAY_COUNTER},
	{"slowdown_temperature", nvml.FI_DEV_PERF_POLICY_THERMAL},
}
