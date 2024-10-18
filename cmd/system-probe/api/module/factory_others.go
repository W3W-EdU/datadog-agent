// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build !linux

package module

import (
	sysconfigtypes "github.com/DataDog/datadog-agent/cmd/system-probe/config/types"
)

// Factory encapsulates the initialization of a Module
type Factory struct {
	Name             sysconfigtypes.ModuleName
	ConfigNamespaces []string
	Fn               func(cfg *sysconfigtypes.Config, deps FactoryDependencies) (Module, error)

	// IgnoreForSuccessCheck can be set to true if system-probe should not consider this module when checking
	// if at least one module was successfully loaded.
	IgnoreForSuccessCheck bool
}
