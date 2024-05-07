// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

//go:build linux_bpf

package postgres

import (
	"sync"

	"github.com/DataDog/datadog-agent/pkg/network/config"
	"github.com/DataDog/datadog-agent/pkg/util/log"
)

// StatKeeper is a struct to hold the records for the postgres protocol
type StatKeeper struct {
	stats      map[Key]*RequestStat
	statsMutex sync.RWMutex
	maxEntries int
}

// NewStatkeeper creates a new StatKeeper
func NewStatkeeper(c *config.Config) *StatKeeper {
	newStatKeeper := &StatKeeper{
		maxEntries: c.MaxPostgresStatsBuffered,
	}
	newStatKeeper.resetNoLock()
	return newStatKeeper
}

// Process processes the postgres transaction
func (s *StatKeeper) Process(tx *EventWrapper) {
	s.statsMutex.Lock()
	defer s.statsMutex.Unlock()

	key := Key{
		Operation:     tx.Operation(),
		TableName:     tx.TableName(),
		ConnectionKey: tx.ConnTuple(),
	}
	requestStats, ok := s.stats[key]
	if !ok {
		if len(s.stats) >= s.maxEntries {
			return
		}
		requestStats = new(RequestStat)
		if err := requestStats.initSketch(); err != nil {
			return
		}
		requestStats.FirstLatencySample = tx.RequestLatency()
		s.stats[key] = requestStats
	}
	requestStats.Count++
	if requestStats.Count == 1 {
		return
	}
	if err := requestStats.Latencies.Add(tx.RequestLatency()); err != nil {
		log.Debugf("could not add request latency to ddsketch: %v", err)
	}
}

// GetAndResetAllStats returns all the records and resets the statskeeper
func (s *StatKeeper) GetAndResetAllStats() map[Key]*RequestStat {
	s.statsMutex.RLock()
	defer s.statsMutex.RUnlock()
	ret := s.stats // No deep copy needed since `s.statskeeper` gets reset
	s.resetNoLock()
	return ret
}

func (s *StatKeeper) resetNoLock() {
	s.stats = make(map[Key]*RequestStat)
}
