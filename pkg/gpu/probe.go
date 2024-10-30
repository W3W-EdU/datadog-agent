// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux_bpf

package gpu

import (
	"fmt"
	"io"
	"os"
	"regexp"

	"github.com/NVIDIA/go-nvml/pkg/nvml"
	"github.com/cilium/ebpf"

	sysconfig "github.com/DataDog/datadog-agent/cmd/system-probe/config"
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	"github.com/DataDog/datadog-agent/pkg/collector/corechecks/gpu/model"
	ddebpf "github.com/DataDog/datadog-agent/pkg/ebpf"
	"github.com/DataDog/datadog-agent/pkg/ebpf/bytecode"
	"github.com/DataDog/datadog-agent/pkg/ebpf/uprobes"
	"github.com/DataDog/datadog-agent/pkg/gpu/config"
	"github.com/DataDog/datadog-agent/pkg/process/monitor"
	"github.com/DataDog/datadog-agent/pkg/util/log"
	manager "github.com/DataDog/ebpf-manager"
)

// probeFuncName stores the ebpf hook function name
type probeFuncName = string

// bpfMapName stores the name of the BPF maps storing statistics and other info
type bpfMapName = string

const (
	cudaEventsMap     bpfMapName = "cuda_events"
	cudaAllocCacheMap bpfMapName = "cuda_alloc_cache"
	cudaSyncCacheMap  bpfMapName = "cuda_sync_cache"

	cudaLaunchKernelProbe  probeFuncName = "uprobe__cudaLaunchKernel"
	cudaMallocProbe        probeFuncName = "uprobe__cudaMalloc"
	cudaMallocRetProbe     probeFuncName = "uretprobe__cudaMalloc"
	cudaStreamSyncProbe    probeFuncName = "uprobe__cudaStreamSynchronize"
	cudaStreamSyncRetProbe probeFuncName = "uretprobe__cudaStreamSynchronize"
	cudaFreeProbe          probeFuncName = "uprobe__cudaFree"
)
const (
	gpuAttacherName = "gpu"
)

const consumerChannelSize = 4096

// ProbeDependencies holds the dependencies for the probe
type ProbeDependencies struct {
	// Telemetry is the telemetry component
	Telemetry telemetry.Component

	// NvmlLib is the NVML library interface
	NvmlLib nvml.Interface
}

// Probe represents the GPU monitoring probe
type Probe struct {
	m              *ddebpf.Manager
	cfg            *config.Config
	consumer       *cudaEventConsumer
	attacher       *uprobes.UprobeAttacher
	statsGenerator *statsGenerator
	deps           ProbeDependencies
}

// NewProbe starts the GPU monitoring probe, setting up the eBPF program and the uprobes, the
// consumers for the events generated from the uprobes, and the stats generator to aggregate the data from
// streams into per-process GPU stats.
func NewProbe(cfg *config.Config, deps ProbeDependencies) (*Probe, error) {
	if err := config.CheckGPUSupported(); err != nil {
		return nil, err
	}
	log.Tracef("starting %s probe...", sysconfig.GPUMonitoringModule)

	allowRC := cfg.EnableRuntimeCompiler && cfg.AllowRuntimeCompiledFallback
	var m *ddebpf.Manager
	var err error

	//try CO-RE first
	if cfg.EnableCORE {
		m, err = getCOREGPU(cfg)

		if err != nil {
			if allowRC {
				log.Warnf("error loading CO-RE %s, falling back to runtime compiled: %v", sysconfig.GPUMonitoringModule, err)
			} else {
				return nil, fmt.Errorf("error loading CO-RE %s: %w", sysconfig.GPUMonitoringModule, err)
			}
		}
	}

	//if manager is not initialized yet and RC is enabled, try runtime compilation
	if m == nil && allowRC {
		m, err = getRCGPU(cfg)
		if err != nil {
			return nil, fmt.Errorf("unable to compile %s probe: %w", sysconfig.GPUMonitoringModule, err)
		}
	}

	probe, err := start(m, deps, cfg)
	if err != nil {
		return nil, err
	}

	return probe, nil
}

func getRCGPU(cfg *config.Config) (*ddebpf.Manager, error) {
	buf, err := getRuntimeCompiledGPUMonitoring(cfg)
	if err != nil {
		return nil, err
	}
	defer buf.Close()

	return getManager(buf, manager.Options{})
}

func getCOREGPU(cfg *config.Config) (*ddebpf.Manager, error) {
	asset := getAssetName("gpu", cfg.BPFDebug)
	var m *ddebpf.Manager
	var err error
	err = ddebpf.LoadCOREAsset(asset, func(ar bytecode.AssetReader, o manager.Options) error {
		m, err = getManager(ar, o)
		return err
	})
	return m, err
}

func getAssetName(module string, debug bool) string {
	if debug {
		return fmt.Sprintf("%s-debug.o", module)
	}

	return fmt.Sprintf("%s.o", module)
}

func getManager(buf io.ReaderAt, opts manager.Options) (*ddebpf.Manager, error) {
	m := ddebpf.NewManagerWithDefault(&manager.Manager{
		Probes: []*manager.Probe{
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: cudaLaunchKernelProbe,
				},
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: cudaMallocProbe,
				},
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: cudaMallocRetProbe,
				},
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: cudaStreamSyncProbe,
				},
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: cudaStreamSyncRetProbe,
				},
			},
			{
				ProbeIdentificationPair: manager.ProbeIdentificationPair{
					EBPFFuncName: cudaFreeProbe,
				},
			},
		},
		Maps: []*manager.Map{
			{
				Name: cudaAllocCacheMap,
			},
			{
				Name: cudaEventsMap,
			},
			{
				Name: cudaSyncCacheMap,
			},
		}})

	if opts.MapSpecEditors == nil {
		opts.MapSpecEditors = make(map[string]manager.MapSpecEditor)
	}

	// Ring buffer size has to be a multiple of the page size, and we want to have at least 4096 bytes
	pagesize := os.Getpagesize()
	ringbufSize := pagesize
	minRingbufSize := 4096
	if minRingbufSize > ringbufSize {
		ringbufSize = (minRingbufSize/pagesize + 1) * pagesize
	}

	opts.MapSpecEditors[cudaEventsMap] = manager.MapSpecEditor{
		Type:       ebpf.RingBuf,
		MaxEntries: uint32(ringbufSize),
		KeySize:    0,
		ValueSize:  0,
		EditorFlag: manager.EditType | manager.EditMaxEntries | manager.EditKeyValue,
	}

	if err := m.InitWithOptions(buf, &opts); err != nil {
		return nil, fmt.Errorf("failed to init manager: %w", err)
	}

	return m, nil
}

// TODO: in the future consider replacing that with a proper state management via public Init and Start methods.
// for now we can keep this for simplicity
func start(m *ddebpf.Manager, deps ProbeDependencies, cfg *config.Config) (*Probe, error) {

	// Note: this will later be replaced by a common way to enable the process monitor across system-probe
	procMon := monitor.GetProcessMonitor()
	if err := procMon.Initialize(false); err != nil {
		return nil, fmt.Errorf("error initializing process monitor: %w", err)
	}

	attachCfg := uprobes.AttacherConfig{
		Rules: []*uprobes.AttachRule{
			{
				LibraryNameRegex: regexp.MustCompile(`libcudart\.so`),
				Targets:          uprobes.AttachToExecutable | uprobes.AttachToSharedLibraries,
				ProbesSelector: []manager.ProbesSelector{
					&manager.AllOf{
						Selectors: []manager.ProbesSelector{
							&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{EBPFFuncName: cudaLaunchKernelProbe}},
							&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{EBPFFuncName: cudaMallocProbe}},
							&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{EBPFFuncName: cudaMallocRetProbe}},
							&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{EBPFFuncName: cudaStreamSyncProbe}},
							&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{EBPFFuncName: cudaStreamSyncRetProbe}},
							&manager.ProbeSelector{ProbeIdentificationPair: manager.ProbeIdentificationPair{EBPFFuncName: cudaFreeProbe}},
						},
					},
				},
			},
		},
		EbpfConfig:         &cfg.Config,
		PerformInitialScan: cfg.InitialProcessSync,
	}

	attacher, err := uprobes.NewUprobeAttacher(gpuAttacherName, attachCfg, m, nil, &uprobes.NativeBinaryInspector{})
	if err != nil {
		return nil, fmt.Errorf("error creating uprobes attacher: %w", err)
	}

	p := &Probe{
		m:        m,
		cfg:      cfg,
		attacher: attacher,
		deps:     deps,
	}

	sysCtx, err := getSystemContext(deps.NvmlLib)
	if err != nil {
		return nil, fmt.Errorf("error getting system context: %w", err)
	}

	now, err := ddebpf.NowNanoseconds()
	if err != nil {
		return nil, fmt.Errorf("error getting current time: %w", err)
	}

	p.startEventConsumer()
	p.statsGenerator = newStatsGenerator(sysCtx, now, p.consumer.streamHandlers)

	if err := m.Start(); err != nil {
		return nil, fmt.Errorf("failed to start manager: %w", err)
	}

	if err := attacher.Start(); err != nil {
		return nil, fmt.Errorf("error starting uprobes attacher: %w", err)
	}

	return p, nil
}

// Close stops the probe
func (p *Probe) Close() {
	if p.attacher != nil {
		p.attacher.Stop()
	}

	_ = p.m.Stop(manager.CleanAll)

	if p.consumer != nil {
		p.consumer.Stop()
	}
}

// GetAndFlush returns the GPU stats
func (p *Probe) GetAndFlush() (*model.GPUStats, error) {
	now, err := ddebpf.NowNanoseconds()
	if err != nil {
		return nil, fmt.Errorf("error getting current time: %w", err)
	}

	stats := p.statsGenerator.getStats(now)

	p.cleanupFinished()

	return stats, nil
}

func (p *Probe) cleanupFinished() {
	p.statsGenerator.cleanupFinishedAggregators()
	p.consumer.cleanFinishedHandlers()
}

func (p *Probe) startEventConsumer() {
	handler := ddebpf.NewRingBufferHandler(consumerChannelSize)
	rb := &manager.RingBuffer{
		Map: manager.Map{Name: cudaEventsMap},
		RingBufferOptions: manager.RingBufferOptions{
			RecordHandler: handler.RecordHandler,
			RecordGetter:  handler.RecordGetter,
		},
	}
	p.m.RingBuffers = append(p.m.RingBuffers, rb)
	p.consumer = newCudaEventConsumer(handler, p.cfg)
	p.consumer.Start()
}
