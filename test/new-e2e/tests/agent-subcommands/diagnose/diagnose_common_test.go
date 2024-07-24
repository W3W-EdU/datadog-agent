// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2016-present Datadog, Inc.

package diagnose

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/e2e"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/environments"
	"github.com/DataDog/datadog-agent/test/new-e2e/pkg/utils/e2e/client/agentclient"

	"github.com/DataDog/datadog-agent/pkg/diagnose/diagnosis"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type baseDiagnoseSuite struct {
	e2e.BaseSuite[environments.Host]

	suites []string
}

var commonSuites = []string{
	"check-datadog",
	"connectivity-datadog-autodiscovery",
	"connectivity-datadog-core-endpoints",
	"connectivity-datadog-event-platform",
}

// type summary represents the number of success, fail, warnings and errors of a diagnose command
type summary struct {
	total    int
	success  int
	warnings int
	fail     int
	errors   int
}

func getDiagnoseOutput(v *baseDiagnoseSuite, commandArgs ...agentclient.AgentArgsOption) string {
	require.EventuallyWithT(v.T(), func(c *assert.CollectT) {
		assert.NoError(c, v.Env().FakeIntake.Client().GetServerHealth())
	}, 5*time.Minute, 20*time.Second, "timedout waiting for fakeintake to be healthy")

	diagnose := v.Env().Agent.Client.Diagnose(commandArgs...)
	return diagnose
}

func (v *baseDiagnoseSuite) TestDiagnoseDefaultConfig() {
	diagnose := getDiagnoseOutput(v)
	v.AssertOutputNotError(diagnose)

	diagnose = getDiagnoseOutput(v, agentclient.WithArgs([]string{"--json"}))
	diagnoseJSON := stringToJSON(diagnose)
	assert.NotNil(v.T(), diagnoseJSON)
	assert.Zero(v.T(), diagnoseJSON.Summary.Fail)
	assert.Zero(v.T(), diagnoseJSON.Summary.UnexpectedErr)
}

func (v *baseDiagnoseSuite) TestDiagnoseLocal() {
	diagnose := getDiagnoseOutput(v, agentclient.WithArgs([]string{"--local"}))
	v.AssertOutputNotError(diagnose)

	diagnose = getDiagnoseOutput(v, agentclient.WithArgs([]string{"--json", "--local"}))
	diagnoseJSON := stringToJSON(diagnose)
	assert.NotNil(v.T(), diagnoseJSON)
	assert.Zero(v.T(), diagnoseJSON.Summary.Fail)
	assert.Zero(v.T(), diagnoseJSON.Summary.UnexpectedErr)
}

func (v *baseDiagnoseSuite) TestDiagnoseList() {
	diagnose := getDiagnoseOutput(v, agentclient.WithArgs([]string{"--list"}))
	for _, suite := range v.suites {
		assert.Contains(v.T(), diagnose, suite)
	}

	diagnose = getDiagnoseOutput(v, agentclient.WithArgs([]string{"--json", "--list"}))
	diagnoseJSON := stringToJSON(diagnose)
	assert.NotNil(v.T(), diagnoseJSON)
	for _, suite := range diagnoseJSON.Diagnoses {
		assert.Contains(v.T(), v.suites, suite.SuiteName)
	}
}

func (v *baseDiagnoseSuite) AssertDiagnoseInclude() {
	diagnose := getDiagnoseOutput(v)
	diagnoseSummary := getDiagnoseSummary(diagnose)
	for _, suite := range v.suites {
		diagnoseInclude := getDiagnoseOutput(v, agentclient.WithArgs([]string{"--include", suite}))
		resultInclude := getDiagnoseSummary(diagnoseInclude)

		assert.Less(v.T(), resultInclude.total, diagnoseSummary.total, "Expected number of checks for suite %v to be lower than the total amount of checks (%v) but was %v", suite, diagnoseSummary.total, resultInclude.total)
		assert.Zero(v.T(), resultInclude.fail)
		assert.Zero(v.T(), resultInclude.errors)
	}

	// Create an args array to include all suites
	includeArgs := strings.Split("--include "+strings.Join(v.suites, " --include "), " ")

	// Diagnose with all suites included should be equal to diagnose without args
	diagnoseIncludeEverySuite := getDiagnoseOutput(v, agentclient.WithArgs(includeArgs))
	diagnoseIncludeEverySuiteSummary := getDiagnoseSummary(diagnoseIncludeEverySuite)
	assert.Equal(v.T(), diagnoseIncludeEverySuiteSummary, diagnoseSummary)
}

func (v *baseDiagnoseSuite) AssertDiagnoseJSONInclude() {
	diagnose := getDiagnoseOutput(v, agentclient.WithArgs([]string{"--json"}))
	diagnoseResult := stringToJSON(diagnose)
	assert.NotNil(v.T(), diagnoseResult)
	diagnoseSummary := diagnoseResult.Summary
	for _, suite := range v.suites {
		diagnoseInclude := getDiagnoseOutput(v, agentclient.WithArgs([]string{"--json", "--include", suite}))
		diagnoseIncludeResult := stringToJSON(diagnoseInclude)
		assert.NotNil(v.T(), diagnoseIncludeResult)

		resultInclude := diagnoseIncludeResult.Summary

		assert.Less(v.T(), resultInclude.Total, diagnoseSummary.Total, "Expected number of checks for suite %v to be lower than the total amount of checks (%v) but was %v", suite, diagnoseSummary.Total, resultInclude.Total)
		assert.Zero(v.T(), resultInclude.Fail)
		assert.Zero(v.T(), resultInclude.UnexpectedErr)
	}

	// Create an args array to include all suites
	includeArgs := strings.Split(" --json "+" --include "+strings.Join(v.suites, " --include "), " ")

	// Diagnose with all suites included should be equal to diagnose without args
	diagnoseIncludeEverySuite := getDiagnoseOutput(v, agentclient.WithArgs(includeArgs))
	diagnoseIncludeEverySuiteResult := stringToJSON(diagnoseIncludeEverySuite)
	assert.NotNil(v.T(), diagnoseIncludeEverySuiteResult)
	assert.Equal(v.T(), diagnoseIncludeEverySuiteResult.Summary, diagnoseSummary)
}

func (v *baseDiagnoseSuite) AssertDiagnoseExclude() {
	for _, suite := range v.suites {
		diagnoseExclude := getDiagnoseOutput(v, agentclient.WithArgs([]string{"--exclude", suite}))
		resultExclude := getDiagnoseSummary(diagnoseExclude)

		assert.Equal(v.T(), resultExclude.fail, 0)
		assert.Equal(v.T(), resultExclude.errors, 0)
	}

	// Create an args array to exclude all suites
	excludeArgs := strings.Split(" --exclude "+strings.Join(v.suites, " --exclude "), " ")

	// Diagnose with all suites excluded should do nothing
	diagnoseExcludeEverySuite := getDiagnoseOutput(v, agentclient.WithArgs(excludeArgs))
	summary := getDiagnoseSummary(diagnoseExcludeEverySuite)
	assert.Equal(v.T(), summary.total, 0)
}

func (v *baseDiagnoseSuite) AssertDiagnoseJSONExclude() {
	for _, suite := range v.suites {
		diagnoseExclude := getDiagnoseOutput(v, agentclient.WithArgs([]string{"--json", "--exclude", suite}))
		diagnoseExcludeResult := stringToJSON(diagnoseExclude)
		assert.NotNil(v.T(), diagnoseExcludeResult)

		resultExclude := diagnoseExcludeResult.Summary

		assert.Equal(v.T(), resultExclude.Fail, 0)
		assert.Equal(v.T(), resultExclude.UnexpectedErr, 0)
	}

	// Create an args array to exclude all suites
	excludeArgs := strings.Split(" --json "+" --exclude "+strings.Join(v.suites, " --exclude "), " ")

	// Diagnose with all suites excluded should do nothing
	diagnoseExcludeEverySuite := getDiagnoseOutput(v, agentclient.WithArgs(excludeArgs))
	diagnoseExcludeEverySuiteResult := stringToJSON(diagnoseExcludeEverySuite)
	assert.NotNil(v.T(), diagnoseExcludeEverySuiteResult)
	assert.Equal(v.T(), diagnoseExcludeEverySuiteResult.Summary.Total, 0)

}

func (v *baseDiagnoseSuite) TestDiagnoseVerbose() {
	diagnose := getDiagnoseOutput(v, agentclient.WithArgs([]string{"-v"}))
	summary := getDiagnoseSummary(diagnose)

	re := regexp.MustCompile("PASS")
	matches := re.FindAllString(diagnose, -1)

	// Verify that verbose mode display extra information such 'PASS' for successful checks
	assert.Equal(v.T(), len(matches), summary.total, "Expected to have the same number of 'PASS' as the number of checks (%v), but was %v", summary.total, len(matches))
	assert.Contains(v.T(), diagnose, "connectivity-datadog-core-endpoints")
}

func (v *baseDiagnoseSuite) TestDiagnoseJSON() {
	diagnose := getDiagnoseOutput(v, agentclient.WithArgs([]string{"-v", "--json"}))
	diagnoseResult := stringToJSON(diagnose)
	assert.NotNil(v.T(), diagnoseResult)

	summary := diagnoseResult.Summary

	// Verify that verbose mode displays extra information such as 'PASS' for successful checks
	assert.Equal(v.T(), summary.Success, summary.Total, "Expected to have the same number of 'PASS' as the number of checks (%v), but was %v", summary.Total, summary.Success)
	assert.Contains(v.T(), diagnose, "connectivity-datadog-core-endpoints")
}

func (v *baseDiagnoseSuite) AssertOutputNotError(diagnose string) {
	assert.NotContains(v.T(), diagnose, "FAIL")
	assert.NotContains(v.T(), diagnose, "UNEXPECTED ERROR")
}

var summaryRE = createSummaryRegex()

func createSummaryRegex() *regexp.Regexp {
	// success, fail, warning and error are optional in the diagnose output (they're printed when their value != 0)
	successRegex := `(?:, Success:(?P<success>\d+))?`
	failRegex := `(?:, Fail:(?P<fail>\d+))?`
	warningRegex := `(?:, Warning:(?P<warning>\d+))?`
	errorRegex := `(?:, Error:(?P<error>\d+))?`
	regexTemplate := `Total:(?P<total>\d+)` + successRegex + failRegex + warningRegex + errorRegex

	return regexp.MustCompile(regexTemplate)
}

// getDiagnoseSummary parses the diagnose output and returns a struct containing number of success, fail, error and warning
func getDiagnoseSummary(diagnoseOutput string) summary {
	matches := summaryRE.FindStringSubmatch(diagnoseOutput)

	return summary{
		total:    getRegexGroupValue(summaryRE, matches, "total"),
		success:  getRegexGroupValue(summaryRE, matches, "success"),
		warnings: getRegexGroupValue(summaryRE, matches, "warning"),
		fail:     getRegexGroupValue(summaryRE, matches, "fail"),
		errors:   getRegexGroupValue(summaryRE, matches, "error"),
	}
}

// getRegexGroupValue returns the value of a specific named group, or 0 if there is no value for this group
func getRegexGroupValue(re *regexp.Regexp, matches []string, groupName string) int {
	index := re.SubexpIndex(groupName)
	if index < 0 || index >= len(matches) {
		panic(fmt.Sprintf("An error occurred while looking for group '%v' in diagnose output", groupName))
	}

	val, err := strconv.Atoi(matches[index])
	if err != nil {
		return 0
	}

	return val
}

// stringToJSON converts a diagnose string to a DiagnoseResult struct
func stringToJSON(s string) *diagnosis.DiagnoseResult {
	result := &diagnosis.DiagnoseResult{}
	err := json.Unmarshal([]byte(s), result)
	if err != nil {
		return nil
	}
	return result
}
