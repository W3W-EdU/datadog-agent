// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package gpu

import (
	"fmt"

	"github.com/NVIDIA/go-nvml/pkg/nvml"

	"github.com/DataDog/datadog-agent/pkg/gpu/cuda"
	"github.com/DataDog/datadog-agent/pkg/util/ktime"
)

// systemContext holds certain attributes about the system that are used by the GPU probe.
type systemContext struct {
	// maxGpuThreadsPerDevice maps each device index to the maximum number of threads it can run in parallel
	maxGpuThreadsPerDevice map[int]int

	// timeResolver allows to resolve kernel-time timestamps
	timeResolver *ktime.Resolver

	// nvmlLib is the NVML library used to query GPU devices
	nvmlLib nvml.Interface

	// selectedDeviceByPIDAndTID maps each process ID to the map of thread IDs to selected device index.
	// The reason to have a nested map is to allow easy cleanup of data when a process exits.
	// The thread ID is important as the device selection in CUDA is per-thread.
	// Note that this is the device index as seen by the process itself, which might
	// be modified by the CUDA_VISIBLE_DEVICES environment variable later
	selectedDeviceByPIDAndTID map[int]map[int]int32

	// gpuDevices is the list of GPU devices on the system
	gpuDevices []nvml.Device

	// procRoot is the path to the procfs root
	procRoot string

	// visibleDevicesCache is a cache of visible devices for each process, to avoid
	// looking into the environment variables every time
	visibleDevicesCache map[int][]nvml.Device
}

func getSystemContext(nvmlLib nvml.Interface, procRoot string) (*systemContext, error) {
	ctx := &systemContext{
		maxGpuThreadsPerDevice:    make(map[int]int),
		nvmlLib:                   nvmlLib,
		procRoot:                  procRoot,
		selectedDeviceByPIDAndTID: make(map[int]map[int]int32),
		visibleDevicesCache:       make(map[int][]nvml.Device),
	}

	if err := ctx.queryDevices(); err != nil {
		return nil, fmt.Errorf("error querying devices: %w", err)
	}

	var err error
	ctx.timeResolver, err = ktime.NewResolver()
	if err != nil {
		return nil, fmt.Errorf("error creating time resolver: %w", err)
	}

	return ctx, nil
}

func (ctx *systemContext) queryDevices() error {
	var err error
	ctx.gpuDevices, err = getGPUDevices(ctx.nvmlLib)
	if err != nil {
		return fmt.Errorf("error getting GPU devices: %w", err)
	}

	for i, device := range ctx.gpuDevices {
		maxThreads, err := getMaxThreadsForDevice(device)
		if err != nil {
			return fmt.Errorf("error getting max threads for device %s: %w", device, err)
		}

		ctx.maxGpuThreadsPerDevice[i] = maxThreads
	}

	return nil
}

func (ctx *systemContext) getCurrentActiveGpuDevice(pid int, tid int) (*nvml.Device, error) {
	visibleDevices, ok := ctx.visibleDevicesCache[pid]
	if !ok {
		visibleDevices, err := cuda.GetVisibleDevicesForProcess(ctx.gpuDevices, pid, ctx.procRoot)
		if err != nil {
			return nil, fmt.Errorf("error getting visible devices for process %d: %w", pid, err)
		}

		ctx.visibleDevicesCache[pid] = visibleDevices
	}

	if len(visibleDevices) == 0 {
		return nil, fmt.Errorf("no GPU devices for process %d", pid)
	}

	selectedDeviceIndex := int32(0)
	pidMap, ok := ctx.selectedDeviceByPIDAndTID[pid]
	if ok {
		selectedDeviceIndex = pidMap[tid] // Defaults to 0, which is the same as CUDA
	}

	if selectedDeviceIndex < 0 || selectedDeviceIndex >= int32(len(visibleDevices)) {
		return nil, fmt.Errorf("device index %d is out of range", selectedDeviceIndex)
	}

	return &visibleDevices[selectedDeviceIndex], nil
}

func (ctx *systemContext) setDeviceSelection(pid int, tid int, deviceIndex int32) {
	if _, ok := ctx.selectedDeviceByPIDAndTID[pid]; !ok {
		ctx.selectedDeviceByPIDAndTID[pid] = make(map[int]int32)
	}

	ctx.selectedDeviceByPIDAndTID[pid][tid] = deviceIndex
}
