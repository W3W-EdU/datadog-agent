// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

// Package catalog is a wrapper that loads the available workloadmeta
// collectors. It exists as a shorthand for importing all packages manually in
// all of the agents.
package catalog

import (
	"github.com/DataDog/datadog-agent/comp/core/config"
	wmcatalog "github.com/DataDog/datadog-agent/comp/core/wmcatalog/def"
)

// GetCatalog returns the set of collectors in the catalog
func GetCatalog(cfg config.Component) []wmcatalog.Collector {
	return getCollectorList(cfg)
}
