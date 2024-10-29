// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2023-present Datadog, Inc.

package tagger

import (
	"github.com/DataDog/datadog-agent/comp/core/tagger/types"
)

// Params provides the kind of agent we're instantiating workloadmeta for
type Params struct {
	RemoteFilter       *types.Filter
	RemoteTarget       string
	RemoteTokenFetcher func() (string, error)
}

// // NewTaggerParamsForCoreAgent is a constructor function for creating core agent tagger params
// func NewTaggerParamsForCoreAgent(_ config.Component) Params {
// 	if pkgconfigsetup.IsCLCRunner(pkgconfigsetup.Datadog()) {
// 		return NewCLCRunnerRemoteTaggerParams()
// 	}
// 	return NewTaggerParams()
// }
