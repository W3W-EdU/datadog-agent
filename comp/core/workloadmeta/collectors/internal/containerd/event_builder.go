// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build containerd

package containerd

import (
	"errors"
	"fmt"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/api/events"
	containerdevents "github.com/containerd/containerd/events"
	"google.golang.org/protobuf/proto"

	"github.com/DataDog/datadog-agent/comp/core/workloadmeta"
	cutil "github.com/DataDog/datadog-agent/pkg/util/containerd"
)

var errNoContainer = errors.New("no container")

// buildCollectorEvent generates a CollectorEvent from a containerdevents.Envelope
func (c *collector) buildCollectorEvent(
	containerdEvent *containerdevents.Envelope,
	containerID string,
	container containerd.Container,
	store workloadmeta.Component,
) (workloadmeta.CollectorEvent, error) {
	switch containerdEvent.Topic {
	case containerCreationTopic, containerUpdateTopic:
		return createSetEvent(container, containerdEvent.Namespace, c.containerdClient, store)

	case containerDeletionTopic:
		exitInfo := c.getExitInfo(containerID)
		defer c.deleteExitInfo(containerID)

		return createDeletionEvent(containerID, exitInfo), nil

	case TaskExitTopic:
		exited := &events.TaskExit{}
		if err := proto.Unmarshal(containerdEvent.Event.GetValue(), exited); err != nil {
			return workloadmeta.CollectorEvent{}, err
		}

		c.cacheExitInfo(containerID, &exited.ExitStatus, exited.ExitedAt.AsTime())
		return createSetEvent(container, containerdEvent.Namespace, c.containerdClient, store)

	case TaskDeleteTopic:
		deleted := &events.TaskDelete{}
		if err := proto.Unmarshal(containerdEvent.Event.GetValue(), deleted); err != nil {
			return workloadmeta.CollectorEvent{}, err
		}

		c.cacheExitInfo(containerID, &deleted.ExitStatus, deleted.ExitedAt.AsTime())
		return createSetEvent(container, containerdEvent.Namespace, c.containerdClient, store)

	case TaskStartTopic, TaskOOMTopic, TaskPausedTopic, TaskResumedTopic:
		return createSetEvent(container, containerdEvent.Namespace, c.containerdClient, store)

	default:
		return workloadmeta.CollectorEvent{}, fmt.Errorf("unknown action type %s, ignoring", containerdEvent.Topic)
	}
}

func createSetEvent(
	container containerd.Container,
	namespace string,
	containerdClient cutil.ContainerdItf,
	store workloadmeta.Component) (workloadmeta.CollectorEvent, error) {
	if container == nil {
		return workloadmeta.CollectorEvent{}, errNoContainer
	}

	entity, err := buildWorkloadMetaContainer(namespace, container, containerdClient, store)
	if err != nil {
		return workloadmeta.CollectorEvent{}, fmt.Errorf("could not fetch info for container %s: %s", container.ID(), err)
	}

	// The namespace cannot be obtained from a container instance. That's why we
	// propagate it here using the one in the event.
	entity.Namespace = namespace

	return workloadmeta.CollectorEvent{
		Type:   workloadmeta.EventTypeSet,
		Source: workloadmeta.SourceRuntime,
		Entity: &entity,
	}, nil
}

func createDeletionEvent(containerID string, exitInfo *exitInfo) workloadmeta.CollectorEvent {
	container := &workloadmeta.Container{
		EntityID: workloadmeta.EntityID{
			Kind: workloadmeta.KindContainer,
			ID:   containerID,
		},
	}

	if exitInfo != nil {
		exitcode := int32(*exitInfo.exitCode)
		container.State.ExitCode = &exitcode
		container.State.FinishedAt = exitInfo.exitTS
	}

	return workloadmeta.CollectorEvent{
		Type:   workloadmeta.EventTypeUnset,
		Source: workloadmeta.SourceRuntime,
		Entity: container,
	}
}
