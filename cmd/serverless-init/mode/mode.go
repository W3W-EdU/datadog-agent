// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package mode

import (
	serverlessLog "github.com/DataDog/datadog-agent/cmd/serverless-init/log"
	"os"
)

const (
	modeEnvVar        = "DD_SERVERLESS_MODE"
	initLoggerName    = "SERVERLESS_INIT"
	sidecarLoggerName = "SERVERLESS_SIDECAR"
)

func DetectMode() (string, func(logConfig *serverlessLog.Config)) {
	defaultModeRunner := RunInit
	defaultLoggerName := initLoggerName

	if os.Getenv(modeEnvVar) == "sidecar" {
		defaultModeRunner = RunSidecar
		defaultLoggerName = sidecarLoggerName
	}

	return defaultLoggerName, defaultModeRunner
}
