// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package catalog is a wrapper that loads workloadmeta collectors, while having less
// than the full set. Currently only used by the dogstatsd binary, this catalog does
// not include the process-collector due to its increased dependency set.
package catalog

import (
	"github.com/DataDog/datadog-agent/comp/core/config"
	wmcatalog "github.com/DataDog/datadog-agent/comp/core/wmcatalog/def"
	cfcontainer "github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/cloudfoundry/container"
	cfvm "github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/cloudfoundry/vm"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/containerd"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/docker"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/ecs"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/ecsfargate"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/host"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/kubeapiserver"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/kubelet"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/kubemetadata"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/podman"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/remote/processcollector"
	remoteworkloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/internal/remote/workloadmeta"
	"github.com/DataDog/datadog-agent/comp/core/workloadmeta/collectors/util"
	workloadmeta "github.com/DataDog/datadog-agent/comp/core/workloadmeta/def"
	"github.com/DataDog/datadog-agent/pkg/util/flavor"
)

func getCollectorList(cfg config.Component) []wmcatalog.Collector {
	var filter *workloadmeta.Filter // Nil filter accepts everything

	// Security Agent is only interested in containers
	// TODO: (components) create a Catalog component, the implementation used by
	// security-agent can use this filter, instead of needing to check agent.flavor
	if flavor.GetFlavor() == flavor.SecurityAgent {
		filter = workloadmeta.NewFilterBuilder().AddKind(workloadmeta.KindContainer).Build()
	}

	return util.BuildCatalog(
		cfg,
		cfcontainer.NewCollector,
		cfvm.NewCollector,
		containerd.NewCollector,
		docker.NewCollector,
		ecs.NewCollector,
		ecsfargate.NewCollector,
		kubeapiserver.NewCollector,
		kubelet.NewCollector,
		kubemetadata.NewCollector,
		podman.NewCollector,
		remoteworkloadmeta.NewCollectorWithFilterFunc(filter),
		processcollector.NewCollector,
		host.NewCollector,
	)
}
