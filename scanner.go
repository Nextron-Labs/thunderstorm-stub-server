package main

import (
	"math"
	"sort"
)

// StringMatch is a single string match within a YARA rule match.
type StringMatch struct {
	Identifier string
	Offset     int
	Data       []byte
}

// Match represents one YARA rule that fired.
type Match struct {
	RuleName    string
	Tags        []string
	Score       int // from YARA meta: score (default 75 per THOR manual)
	Description string
	Author      string
	Strings     []StringMatch
}

// ScanResult holds all YARA matches for a single file.
type ScanResult struct {
	Matches  []Match
	StubMode bool // true when running without real YARA
}

// Scanner is the interface for YARA scanning.
type Scanner interface {
	Scan(data []byte) (ScanResult, error)
	IsStub() bool
	YARAVersion() string
}

// StubScanner always returns no matches. Used when YARA is not compiled in.
type StubScanner struct{}

func (StubScanner) Scan(_ []byte) (ScanResult, error) {
	return ScanResult{StubMode: true}, nil
}

func (StubScanner) IsStub() bool        { return true }
func (StubScanner) YARAVersion() string { return "unavailable (stub mode)" }

const defaultRuleScore = 75

// AccumulateScores combines YARA sub-scores using the THOR accumulation formula:
//
//	total = 100 × (1 − ∏ (1 − s_i/100 / 2^i))
//
// scores must be sorted descending (highest first). Result is capped at 100.
// Single score returns that score unchanged.
// Reference: THOR manual, "Scoring" section.
func AccumulateScores(scores []int) int {
	if len(scores) == 0 {
		return 0
	}
	sorted := make([]int, len(scores))
	copy(sorted, scores)
	sort.Sort(sort.Reverse(sort.IntSlice(sorted)))

	product := 1.0
	for i, s := range sorted {
		product *= 1.0 - float64(s)/100.0/math.Pow(2, float64(i))
	}
	result := int(math.Round(100.0 * (1.0 - product)))
	if result > 100 {
		result = 100
	}
	return result
}

// ScoreToLevel maps a total score and its sub-scores to a THOR severity level.
// Per THOR manual:
//   - > 80  AND any subscore > 75  → Alert
//   - ≥ 60                         → Warning
//   - ≥ 40                         → Notice
//   - < 40                         → Info
func ScoreToLevel(totalScore int, subScores []int) string {
	if totalScore > 80 {
		for _, s := range subScores {
			if s > 75 {
				return "Alert"
			}
		}
		return "Warning"
	}
	if totalScore >= 60 {
		return "Warning"
	}
	if totalScore >= 40 {
		return "Notice"
	}
	return "Info"
}
