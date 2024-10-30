// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

//go:build linux_bpf

package gpu

import (
	"github.com/DataDog/datadog-agent/pkg/gpu/probe"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/pkg/gpu/config"
)

func TestConsumerCanStartAndStop(t *testing.T) {
	cfg := config.NewConfig()
	consumer := newCudaEventConsumer(probe.EventHandler, cfg)

	consumer.Start()
	require.Eventually(t, func() bool { return consumer.running.Load() }, 100*time.Millisecond, 10*time.Millisecond)

	consumer.Stop()
	require.Eventually(t, func() bool { return !consumer.running.Load() }, 100*time.Millisecond, 10*time.Millisecond)
}
