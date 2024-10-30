// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package taggerimpl

import (
	"context"
	"strconv"
	"sync"

	"github.com/DataDog/datadog-agent/comp/core/config"
	taggercommon "github.com/DataDog/datadog-agent/comp/core/tagger/common"
	tagger "github.com/DataDog/datadog-agent/comp/core/tagger/def"
	"github.com/DataDog/datadog-agent/comp/core/tagger/tagstore"
	"github.com/DataDog/datadog-agent/comp/core/tagger/telemetry"
	"github.com/DataDog/datadog-agent/comp/core/tagger/types"

	taggertypes "github.com/DataDog/datadog-agent/pkg/tagger/types"
	"github.com/DataDog/datadog-agent/pkg/tagset"
)

type fakeTagger struct {
	errors         map[string]error
	store          *tagstore.TagStore
	telemetryStore *telemetry.Store
	sync.RWMutex
}

// NewComponent returns a new local tagger
func newfakeTagger(cfg config.Component, telemetryStore *telemetry.Store) tagger.Component {
	return &fakeTagger{
		errors:         make(map[string]error),
		store:          tagstore.NewTagStore(cfg, telemetryStore),
		telemetryStore: telemetryStore,
	}
}

// SetTags allows to set tags in store for a given source, entity
func (f *fakeTagger) SetTags(entityID types.EntityID, source string, low, orch, high, std []string) {
	f.store.ProcessTagInfo([]*types.TagInfo{
		{
			Source:               source,
			EntityID:             entityID,
			LowCardTags:          low,
			OrchestratorCardTags: orch,
			HighCardTags:         high,
			StandardTags:         std,
		},
	})
}

// SetGlobalTags allows to set tags in store for the global entity
func (f *fakeTagger) SetGlobalTags(low, orch, high, std []string) {
	f.SetTags(taggercommon.GetGlobalEntityID(), "static", low, orch, high, std)
}

// SetTagsFromInfo allows to set tags from list of TagInfo
func (f *fakeTagger) SetTagsFromInfo(tags []*types.TagInfo) {
	f.store.ProcessTagInfo(tags)
}

// SetError allows to set an error to be returned when `Tag` or `AccumulateTagsFor` is called
// for this entity and cardinality
func (f *fakeTagger) SetError(entityID types.EntityID, cardinality types.TagCardinality, err error) {
	f.Lock()
	defer f.Unlock()

	f.errors[f.getKey(entityID, cardinality)] = err
}

// Tagger interface

// Start not implemented in fake tagger
func (f *fakeTagger) Start(_ context.Context) error {
	return nil
}

// Stop not implemented in fake tagger
func (f *fakeTagger) Stop() error {
	return nil
}

// ReplayTagger returns the replay tagger instance
// This is a no-op for the fake tagger
func (f *fakeTagger) ReplayTagger() tagger.ReplayTagger {
	return nil
}

// GetTaggerTelemetryStore returns tagger telemetry store
func (f *fakeTagger) GetTaggerTelemetryStore() *telemetry.Store {
	return f.telemetryStore
}

// Tag fake implementation
func (f *fakeTagger) Tag(entityID types.EntityID, cardinality types.TagCardinality) ([]string, error) {
	tags := f.store.Lookup(entityID, cardinality)

	key := f.getKey(entityID, cardinality)
	if err := f.errors[key]; err != nil {
		return nil, err
	}

	return tags, nil
}

// LegacyTag has the same behaviour as the Tag method, but it receives the entity id as a string and parses it.
// If possible, avoid using this function, and use the Tag method instead.
// This function exists in order not to break backward compatibility with rtloader and python
// integrations using the tagger
func (f *fakeTagger) LegacyTag(entity string, cardinality types.TagCardinality) ([]string, error) {
	prefix, id, err := taggercommon.ExtractPrefixAndID(entity)
	if err != nil {
		return nil, err
	}

	entityID := types.NewEntityID(prefix, id)
	return f.Tag(entityID, cardinality)
}

// GlobalTags fake implementation
func (f *fakeTagger) GlobalTags(cardinality types.TagCardinality) ([]string, error) {
	return f.Tag(taggercommon.GetGlobalEntityID(), cardinality)
}

// AccumulateTagsFor fake implementation
func (f *fakeTagger) AccumulateTagsFor(entityID types.EntityID, cardinality types.TagCardinality, tb tagset.TagsAccumulator) error {
	tags, err := f.Tag(entityID, cardinality)
	if err != nil {
		return err
	}

	tb.Append(tags...)
	return nil
}

// Standard fake implementation
func (f *fakeTagger) Standard(entityID types.EntityID) ([]string, error) {
	return f.store.LookupStandard(entityID)
}

// GetEntity returns faked entity corresponding to the specified id and an error
func (f *fakeTagger) GetEntity(entityID types.EntityID) (*types.Entity, error) {
	return f.store.GetEntity(entityID)
}

// List fake implementation
func (f *fakeTagger) List() types.TaggerListResponse {
	return f.store.List()
}

// Subscribe fake implementation
func (f *fakeTagger) Subscribe(subscriptionID string, filter *types.Filter) (types.Subscription, error) {
	return f.store.Subscribe(subscriptionID, filter)
}

// Fake internals
func (f *fakeTagger) getKey(entity types.EntityID, cardinality types.TagCardinality) string {
	return entity.String() + strconv.FormatInt(int64(cardinality), 10)
}

func (f *fakeTagger) GetEntityHash(types.EntityID, types.TagCardinality) string {
	return ""
}

func (f *fakeTagger) AgentTags(types.TagCardinality) ([]string, error) {
	return []string{}, nil
}

func (f *fakeTagger) SetNewCaptureTagger(tagger.Component) {}

func (f *fakeTagger) ResetCaptureTagger() {}

func (f *fakeTagger) EnrichTags(tagset.TagsAccumulator, taggertypes.OriginInfo) {}

func (f *fakeTagger) ChecksCardinality() types.TagCardinality {
	return types.LowCardinality
}

func (f *fakeTagger) DogstatsdCardinality() types.TagCardinality {
	return types.LowCardinality
}
