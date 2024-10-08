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

	// selectedDeviceByPID maps each process ID to the device index it has selected
	// note that this is the device index as seen by the process itself, which might
	// be modified by the CUDA_VISIBLE_DEVICES environment variable later
	selectedDeviceByPID map[int]int

	// gpuDevices is the list of GPU devices on the system
	gpuDevices []nvml.Device

	// procRoot is the path to the procfs root
	procRoot string
}

func getSystemContext(nvmlLib nvml.Interface, procRoot string) (*systemContext, error) {
	ctx := &systemContext{
		maxGpuThreadsPerDevice: make(map[int]int),
		nvmlLib:                nvmlLib,
		procRoot:               procRoot,
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

func (ctx *systemContext) getCurrentActiveGpuDevice(pid int) (*nvml.Device, error) {
	visibleDevices, err := cuda.GetVisibleDevicesForProcess(ctx.gpuDevices, pid, ctx.procRoot)
	if err != nil {
		return nil, fmt.Errorf("error getting visible devices for process %d: %w", pid, err)
	}

	if len(visibleDevices) == 0 {
		return nil, fmt.Errorf("no GPU devices for process %d", pid)
	}

	selectedDeviceIndex := ctx.selectedDeviceByPID[pid] // Defaults to 0, which is the same as CUDA
	if selectedDeviceIndex < 0 || selectedDeviceIndex >= len(visibleDevices) {
		return nil, fmt.Errorf("device index %d is out of range", selectedDeviceIndex)
	}

	return &visibleDevices[selectedDeviceIndex], nil
}
