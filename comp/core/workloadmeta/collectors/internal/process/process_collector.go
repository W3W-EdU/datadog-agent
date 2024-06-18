// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux

// Package process implements the local process collector for Workloadmeta.
package process

import (
	"context"
	"strconv"
	"time"

	"github.com/benbjohnson/clock"
	"go.uber.org/fx"

	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/config"
	"github.com/DataDog/datadog-agent/pkg/errors"
	"github.com/DataDog/datadog-agent/pkg/process/checks"
	processwlm "github.com/DataDog/datadog-agent/pkg/process/metadata/workloadmeta"
	"github.com/DataDog/datadog-agent/pkg/status/health"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

const (
	collectorID   = "local-process-collector"
	componentName = "workloadmeta-process"
)

type collector struct {
	id      string
	store   workloadmeta.Component
	catalog workloadmeta.AgentType

	wlmExtractor  *processwlm.WorkloadMetaExtractor
	processDiffCh <-chan *processwlm.ProcessCacheDiff

	// only used when process checks are disabled
	processData     *checks.ProcessData
	pidToCid        map[int]string
	collectionClock clock.Clock
}

// NewCollector returns a new local process collector provider and an error.
// Currently, this is only used on Linux when language detection and run in core agent are enabled.
func NewCollector() (workloadmeta.CollectorProvider, error) {

	wlmExtractor := processwlm.GetSharedWorkloadMetaExtractor(config.SystemProbe)
	processData := checks.NewProcessData(config.Datadog())
	processData.Register(wlmExtractor)

	return workloadmeta.CollectorProvider{
		Collector: &collector{
			id:              collectorID,
			catalog:         workloadmeta.NodeAgent,
			wlmExtractor:    wlmExtractor,
			processDiffCh:   wlmExtractor.ProcessCacheDiff(),
			processData:     processData,
			pidToCid:        make(map[int]string),
			collectionClock: clock.New(),
		},
	}, nil
}

// GetFxOptions returns the FX framework options for the collector
func GetFxOptions() fx.Option {
	return fx.Provide(NewCollector)
}

func (c *collector) enabled() bool {
	if flavor.GetFlavor() != flavor.DefaultAgent {
		return false
	}

	processChecksInCoreAgent := config.Datadog().GetBool("process_config.run_in_core_agent.enabled")
	langDetectionEnabled := config.Datadog().GetBool("language_detection.enabled")

	return langDetectionEnabled && processChecksInCoreAgent
}

func (c *collector) Start(ctx context.Context, store workloadmeta.Component) error {
	if !c.enabled() {
		return errors.NewDisabled(componentName, "language detection or core agent process collection is disabled")
	}

	c.store = store

	if !config.Datadog().GetBool("process_config.process_collection.enabled") {
		filter := workloadmeta.NewFilterBuilder().AddKind(workloadmeta.KindContainer).Build()
		containerEvt := store.Subscribe(collectorID, workloadmeta.NormalPriority, filter)
		collectionTicker := c.collectionClock.Ticker(10 * time.Second)
		go c.collect(ctx, store, containerEvt, collectionTicker)
	}

	go c.stream(ctx)

	return nil
}

func (c *collector) collect(ctx context.Context, store workloadmeta.Component, containerEvt chan workloadmeta.EventBundle, collectionTicker *clock.Ticker) {
	ctx, cancel := context.WithCancel(ctx)
	defer store.Unsubscribe(containerEvt)
	defer collectionTicker.Stop()
	defer cancel()

	for {
		select {
		case evt, ok := <-containerEvt:
			if !ok {
				log.Infof("The %s collector has stopped, workloadmeta channel is closed", collectorID)
				return
			}
			c.handleContainerEvent(evt)
		case <-collectionTicker.C:
			err := c.processData.Fetch()
			if err != nil {
				log.Error("Error fetching process data:", err)
			}
		case <-ctx.Done():
			log.Infof("The %s collector has stopped", collectorID)
			return
		}
	}
}

func (c *collector) stream(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	health := health.RegisterLiveness(componentName)
	for {
		select {
		case <-health.C:

		case diff := <-c.processDiffCh:
			log.Debugf("Received process diff with %d creations and %d deletions", len(diff.Creation), len(diff.Deletion))
			events := transform(diff)
			c.store.Notify(events)

		case <-ctx.Done():
			err := health.Deregister()
			if err != nil {
				log.Warnf("error de-registering health check: %s", err)
			}
			return
		}
	}
}

func (c *collector) Pull(_ context.Context) error {
	return nil
}

func (c *collector) GetID() string {
	return c.id
}

func (c *collector) GetTargetCatalog() workloadmeta.AgentType {
	return c.catalog
}

// transform converts a ProcessCacheDiff into a list of CollectorEvents.
// The type of event is based whether a process was created or deleted since the last diff.
func transform(diff *processwlm.ProcessCacheDiff) []workloadmeta.CollectorEvent {
	events := make([]workloadmeta.CollectorEvent, 0, len(diff.Creation)+len(diff.Deletion))

	for _, creation := range diff.Creation {
		events = append(events, workloadmeta.CollectorEvent{
			Type: workloadmeta.EventTypeSet,
			Entity: &workloadmeta.Process{
				EntityID: workloadmeta.EntityID{
					Kind: workloadmeta.KindProcess,
					ID:   strconv.Itoa(int(creation.Pid)),
				},
				ContainerID:  creation.ContainerId,
				NsPid:        creation.NsPid,
				CreationTime: time.UnixMilli(creation.CreationTime),
				Language:     creation.Language,
			},
			Source: workloadmeta.SourceLocalProcessCollector,
		})
	}

	for _, deletion := range diff.Deletion {
		events = append(events, workloadmeta.CollectorEvent{
			Type: workloadmeta.EventTypeUnset,
			Entity: &workloadmeta.Process{
				EntityID: workloadmeta.EntityID{
					Kind: workloadmeta.KindProcess,
					ID:   strconv.Itoa(int(deletion.Pid)),
				},
			},
			Source: workloadmeta.SourceLocalProcessCollector,
		})
	}

	return events
}

func (c *collector) handleContainerEvent(evt workloadmeta.EventBundle) {
	defer evt.Acknowledge()

	for _, evt := range evt.Events {
		ent := evt.Entity.(*workloadmeta.Container)
		switch evt.Type {
		case workloadmeta.EventTypeSet:
			// Should be safe, even on windows because PID 0 is the idle process and therefore must always belong to the host
			if ent.PID != 0 {
				c.pidToCid[ent.PID] = ent.ID
			}
		case workloadmeta.EventTypeUnset:
			delete(c.pidToCid, ent.PID)
		}
	}

	c.wlmExtractor.SetLastPidToCid(c.pidToCid)
}
