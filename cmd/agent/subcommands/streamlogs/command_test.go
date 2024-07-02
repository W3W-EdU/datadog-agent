// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package streamlogs

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/DataDog/datadog-agent/cmd/agent/command"
	"github.com/DataDog/datadog-agent/comp/core"
	"github.com/DataDog/datadog-agent/comp/core/secrets"
	"github.com/DataDog/datadog-agent/pkg/util/fxutil"
)

func TestCommand(t *testing.T) {
	fxutil.TestOneShotSubcommand(t,
		Commands(&command.GlobalParams{}),
		[]string{"stream-logs", "--type", "foo", "--duration", "10s", "--output", "output.log"},
		streamLogs,
		func(cliParams *CliParams, coreParams core.BundleParams, secretParams secrets.Params) {
			require.Equal(t, false, secretParams.Enabled)
			require.Equal(t, "foo", cliParams.filters.Type)
			require.Equal(t, 10*time.Second, cliParams.Duration)
			require.Equal(t, "output.log", cliParams.FilePath)
		})
}
