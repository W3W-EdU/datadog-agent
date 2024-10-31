// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package dualimpl

import (
	tagger "github.com/DataDog/datadog-agent/comp/core/tagger/def"
	local "github.com/DataDog/datadog-agent/comp/core/tagger/impl"
	remote "github.com/DataDog/datadog-agent/comp/core/tagger/impl-remote"
)

type Requires struct {
	LocalParams  tagger.Params
	RemoteParams tagger.RemoteParams
	DualParams   tagger.DualParams
}

type Provides struct {
	local.Provides
}

func NewComponent(req Requires) Provides {
	if req.DualParams.UseRemote() {
		remoteRequires := remote.Requires{}
		return Provides{
			local.Provides{
				Comp: remote.NewComponent(remoteRequires).Comp,
			},
		}
	}

	localRequires := local.Requires{}
	return Provides{
		local.NewComponent(localRequires),
	}
}
