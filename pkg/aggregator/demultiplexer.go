// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package aggregator

import (
	"time"

	pkgconfigsetup "github.com/DataDog/datadog-agent/pkg/config/setup"
	"github.com/DataDog/datadog-agent/pkg/metrics"
	"github.com/DataDog/datadog-agent/pkg/tagset"

	"github.com/DataDog/datadog-agent/pkg/aggregator/sender"
	agentruntime "github.com/DataDog/datadog-agent/pkg/runtime"
	"github.com/DataDog/datadog-agent/pkg/serializer"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	// AutoAdjustStrategyMaxThroughput will adapt the number of pipelines for maximum throughput
	AutoAdjustStrategyMaxThroughput = "max_throughput"
	// AutoAdjustStrategyPerOrigin will adapt the number of pipelines for better container isolation
	AutoAdjustStrategyPerOrigin = "per_origin"
)

// Demultiplexer is composed of multiple samplers (check and time/dogstatsd)
// a shared forwarder, the event platform forwarder, orchestrator data buffers
// and other data that need to be sent to the forwarders.
// AgentDemultiplexerOptions let you configure which forwarders have to be started.
type Demultiplexer interface {
	// General
	// --
	// Serializer returns the serializer used by the Demultiplexer instance.
	Serializer() serializer.MetricSerializer

	// Samples API
	// --

	// AggregateSample sends a MetricSample to the DogStatsD time sampler.
	// In sharded implementation, the metric is sent to the first time sampler.
	AggregateSample(sample metrics.MetricSample)
	// AggregateSamples sends a batch of MetricSample to the given DogStatsD
	// time sampler shard.
	// Implementation not supporting sharding may ignore the `shard` parameter.
	AggregateSamples(shard TimeSamplerID, samples metrics.MetricSampleBatch)

	// SendSamplesWithoutAggregation pushes metrics in the no-aggregation pipeline: a pipeline
	// where the metrics are not sampled and sent as-is.
	// This is the method to use to send metrics with a valid timestamp attached.
	SendSamplesWithoutAggregation(metrics metrics.MetricSampleBatch)

	// ForceFlushToSerializer flushes all the aggregated data from the different samplers to
	// the serialization/forwarding parts.
	ForceFlushToSerializer(start time.Time, waitForSerializer bool)
	// GetMetricSamplePool returns a shared resource used in the whole DogStatsD
	// pipeline to re-use metric samples slices: the server is getting a slice
	// and filling it with samples, the rest of the pipeline process them the
	// end of line (the time sampler) is putting back the slice in the pool.
	// Main idea is to reduce the garbage generated by slices allocation.
	GetMetricSamplePool() *metrics.MetricSamplePool

	// Senders API, mainly used by collectors/checks
	// --
	sender.SenderManager
}

// trigger be used to trigger something in the TimeSampler or the BufferedAggregator.
// If `blockChan` is not nil, a message is expected on this chan when the action is done.
// See `flushTrigger` to see the usage in a flush trigger.
type trigger struct {
	time time.Time

	// if not nil, the flusher will send a message in this chan when the flush is complete.
	blockChan chan struct{}

	// used by the BufferedAggregator to know if serialization of events,
	// service checks and such have to be waited for before returning
	// from Flush()
	waitForSerializer bool
}

// flushTrigger is a trigger used to flush data, results is expected to be written
// in flushedSeries (or seriesSink depending on the implementation) and flushedSketches.
type flushTrigger struct {
	trigger

	sketchesSink metrics.SketchesSink
	seriesSink   metrics.SerieSink
}

func createIterableMetrics(
	flushAndSerializeInParallel FlushAndSerializeInParallel,
	serializer serializer.MetricSerializer,
	logPayloads bool,
	isServerless bool,
	hostTagProvider *HostTagProvider,
) (*metrics.IterableSeries, *metrics.IterableSketches) {
	var series *metrics.IterableSeries
	var sketches *metrics.IterableSketches
	hostTags := hostTagProvider.GetHostTags()
	if serializer.AreSeriesEnabled() {
		series = metrics.NewIterableSeries(func(se *metrics.Serie) {
			if logPayloads {
				log.Debugf("Flushing serie: %s", se)
			}

			if hostTags != nil {
				se.Tags = tagset.CombineCompositeTagsAndSlice(se.Tags, hostTagProvider.GetHostTags())
			}
			tagsetTlm.updateHugeSerieTelemetry(se)
		}, flushAndSerializeInParallel.BufferSize, flushAndSerializeInParallel.ChannelSize)
	}
	if serializer.AreSketchesEnabled() {
		sketches = metrics.NewIterableSketches(func(sketch *metrics.SketchSeries) {
			if logPayloads {
				log.Debugf("Flushing Sketches: %v", sketch)
			}
			if isServerless {
				log.DebugfServerless("Sending sketches payload : %s", sketch.String())
			}
			if hostTags != nil {
				sketch.Tags = tagset.CombineCompositeTagsAndSlice(sketch.Tags, hostTagProvider.GetHostTags())
			}
			tagsetTlm.updateHugeSketchesTelemetry(sketch)
		}, flushAndSerializeInParallel.BufferSize, flushAndSerializeInParallel.ChannelSize)
	}
	return series, sketches
}

// sendIterableSeries is continuously sending series to the serializer, until another routine calls SenderStopped on the
// series sink.
// Mainly meant to be executed in its own routine, sendIterableSeries is closing the `done` channel once it has returned
// from SendIterableSeries (because the SenderStopped methods has been called on the sink).
func sendIterableSeries(serializer serializer.MetricSerializer, start time.Time, serieSource metrics.SerieSource) {
	log.Debug("Demultiplexer: sendIterableSeries: start sending iterable series to the serializer")
	err := serializer.SendIterableSeries(serieSource)
	// if err == nil, SenderStopped was called and it is safe to read the number of series.
	count := serieSource.Count()
	addFlushCount("Series", int64(count))
	updateSerieTelemetry(start, count, err)
	log.Debug("Demultiplexer: sendIterableSeries: stop routine")
}

// GetDogStatsDWorkerAndPipelineCount returns how many routines should be spawned
// for the DogStatsD workers and how many DogStatsD pipeline should be running.
func GetDogStatsDWorkerAndPipelineCount() (int, int) {
	work, pipe := getDogStatsDWorkerAndPipelineCount(agentruntime.NumVCPU())
	log.Infof("Dogstatsd configured to run with %d workers and %d pipelines", work, pipe)
	return work, pipe
}

func getDogStatsDWorkerAndPipelineCount(vCPUs int) (int, int) {
	var dsdWorkerCount int
	var pipelineCount int
	autoAdjust := pkgconfigsetup.Datadog().GetBool("dogstatsd_pipeline_autoadjust")
	autoAdjustStrategy := pkgconfigsetup.Datadog().GetString("dogstatsd_pipeline_autoadjust_strategy")

	if autoAdjustStrategy != AutoAdjustStrategyMaxThroughput && autoAdjustStrategy != AutoAdjustStrategyPerOrigin {
		log.Warnf("Invalid value for 'dogstatsd_pipeline_autoadjust_strategy', using default value: %s", AutoAdjustStrategyMaxThroughput)
		autoAdjustStrategy = AutoAdjustStrategyMaxThroughput
	}

	// no auto-adjust of the pipeline count:
	// we use the pipeline count configuration
	// to determine how many workers should be running
	// ------------------------------------

	if !autoAdjust {
		pipelineCount = pkgconfigsetup.Datadog().GetInt("dogstatsd_pipeline_count")
		if pipelineCount <= 0 { // guard against configuration mistakes
			pipelineCount = 1
		}

		// - a core for the listener goroutine
		// - one per aggregation pipeline (time sampler)
		// - the rest for workers
		// But we want at minimum 2 workers.
		dsdWorkerCount = vCPUs - 1 - pipelineCount

		if dsdWorkerCount < 2 {
			dsdWorkerCount = 2
		}
	} else if autoAdjustStrategy == AutoAdjustStrategyMaxThroughput {
		// we will auto-adjust the pipeline and workers count to maximize throughput
		//
		// Benchmarks have revealed that 3 very busy workers can be processed
		// by 2 pipelines DogStatsD and have a good ratio execution / scheduling / waiting.
		// To keep this simple for now, we will try running 1 less pipeline than workers.
		// (e.g. for 4 workers, 3 pipelines)
		// Use Go routines analysis with pprof to look at execution time if you want
		// adapt this heuristic.
		//
		// Basically the formula is:
		//  - half the amount of vCPUS for the amount of workers routines
		//  - half the amount of vCPUS - 1 for the amount of pipeline routines
		//  - this last routine for the listener routine

		dsdWorkerCount = vCPUs / 2
		if dsdWorkerCount < 2 { // minimum 2 workers
			dsdWorkerCount = 2
		}

		pipelineCount = dsdWorkerCount - 1
		if pipelineCount <= 0 { // minimum 1 pipeline
			pipelineCount = 1
		}

		if pkgconfigsetup.Datadog().GetInt("dogstatsd_pipeline_count") > 1 {
			log.Warn("DogStatsD pipeline count value ignored since 'dogstatsd_pipeline_autoadjust' is enabled.")
		}
	} else if autoAdjustStrategy == AutoAdjustStrategyPerOrigin {
		// we will auto-adjust the pipeline and workers count to isolate the pipelines
		//
		// The goal here is to have many pipelines to isolate the processing of the
		// different samplers and avoid contention between them.
		//
		// This also has the benefit of increasing compression efficiency by having
		// similarly tagged metrics flushed together.

		dsdWorkerCount = vCPUs / 2
		if dsdWorkerCount < 2 {
			dsdWorkerCount = 2
		}

		pipelineCount = pkgconfigsetup.Datadog().GetInt("dogstatsd_pipeline_count")
		if pipelineCount <= 0 { // guard against configuration mistakes
			pipelineCount = vCPUs * 2
		}
	}
	log.Info("Dogstatsd workers and pipelines count: ", dsdWorkerCount, " workers, ", pipelineCount, " pipelines")
	return dsdWorkerCount, pipelineCount
}
