// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2024-present Datadog, Inc.

// Package ddflareextensionimpl defines the OpenTelemetry Extension implementation.
package ddflareextensionimpl

import (
	"context"
	"fmt"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/otelcol"

	"github.com/DataDog/datadog-agent/comp/otelcol/ddflareextension/impl/internal/metadata"
)

const (
	defaultHTTPPort = 7777
)

type ddExtensionFactory struct {
	extension.Factory

	factories              *otelcol.Factories
	configProviderSettings otelcol.ConfigProviderSettings
	ocb                    bool
}

// NewFactory creates a factory for Datadog Flare Extension for use with OCB
func NewFactory() extension.Factory {
	factories, err := components()
	if err != nil {
		return nil
	}
	return &ddExtensionFactory{
		factories: &factories,
		ocb:       true,
	}
}

// NewFactoryForAgent creates a factory for Datadog Flare Extension
func NewFactoryForAgent(factories *otelcol.Factories, configProviderSettings otelcol.ConfigProviderSettings) extension.Factory {
	return &ddExtensionFactory{
		factories:              factories,
		configProviderSettings: configProviderSettings,
		ocb:                    false,
	}
}

// CreateExtension exports extension creation
func (f *ddExtensionFactory) CreateExtension(ctx context.Context, set extension.Settings, cfg component.Config) (extension.Extension, error) {
	config := &Config{
		factories:              f.factories,
		configProviderSettings: f.configProviderSettings,
	}
	config.HTTPConfig = cfg.(*Config).HTTPConfig
	return NewExtension(ctx, config, set.TelemetrySettings, set.BuildInfo, f.ocb)
}

// CreateDefaultConfig exports default configuration for use within Datadog Agent
func (f *ddExtensionFactory) CreateDefaultConfig() component.Config {
	return &Config{
		HTTPConfig: &confighttp.ServerConfig{
			Endpoint: fmt.Sprintf("localhost:%d", defaultHTTPPort),
		},
	}
}

func (f *ddExtensionFactory) Type() component.Type {
	return metadata.Type
}

func (f *ddExtensionFactory) ExtensionStability() component.StabilityLevel {
	return metadata.ExtensionStability
}
