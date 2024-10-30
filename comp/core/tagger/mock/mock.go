// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build test
// +build test

package mock

import (
	"net/http"
	"testing"

	"go.uber.org/fx"

	api "github.com/DataDog/datadog-agent/comp/api/api/def"
	"github.com/DataDog/datadog-agent/comp/core/config"
	tagger "github.com/DataDog/datadog-agent/comp/core/tagger/def"
	taggerimpl "github.com/DataDog/datadog-agent/comp/core/tagger/impl"
	taggerTelemetry "github.com/DataDog/datadog-agent/comp/core/tagger/telemetry"
	"github.com/DataDog/datadog-agent/comp/core/tagger/types"
	"github.com/DataDog/datadog-agent/comp/core/telemetry"
	noopTelemetry "github.com/DataDog/datadog-agent/comp/core/telemetry/noopsimpl"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

// Mock implements mock-specific methods for the tagger component.
type Mock interface {
	tagger.Component

	// SetTags allows to set tags in the mock fake tagger
	SetTags(entityID types.EntityID, source string, low, orch, high, std []string)

	// SetGlobalTags allows to set tags in store for the global entity
	SetGlobalTags(low, orch, high, std []string)
}

// mockTaggerClient is a mock of the tagger Component
type mockTaggerClient struct {
	*taggerimpl.FakeTagger
}

// mockHandleRequest is a simple mocked http.Handler function to test the route is registered correctly on the api component
func (m *mockTaggerClient) mockHandleRequest(w http.ResponseWriter, _ *http.Request) {
	w.Write([]byte("OK"))
}

// MockProvides is a mock of the tagger.Component provides struct to test endpoints register properly
type MockProvides struct {
	fx.Out

	Comp     Mock
	Endpoint api.AgentEndpointProvider
}

type dependencies struct {
	fx.In

	Config    config.Component
	Telemetry telemetry.Component
}

// New returns a MockTagger
func New(deps dependencies) MockProvides {
	telemetryStore := taggerTelemetry.NewStore(deps.Telemetry)
	taggerClient := taggerimpl.NewFakeTagger(deps.Config, telemetryStore)
	c := &mockTaggerClient{
		taggerClient,
	}
	return MockProvides{
		Comp:     c,
		Endpoint: api.NewAgentEndpointProvider(c.mockHandleRequest, "/tagger-list", "GET"),
	}
}

// MockModule is a module containing the mock, useful for testing
func MockModule() fxutil.Module {
	return fxutil.Component(
		fx.Provide(New),
		fx.Supply(config.Params{}),
		config.MockModule(),
		noopTelemetry.Module(),
	)
}

// SetupFakeTagger calls fxutil.Test to create a mock tagger for testing
func SetupFakeTagger(t *testing.T) Mock {
	return fxutil.Test[Mock](t, MockModule())
}
