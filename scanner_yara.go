//go:build yara

package main

// To enable YARA support:
//   1. Install libyara >= 4: brew install yara  (macOS)  /  apt install libyara-dev  (Debian/Ubuntu)
//   2. go get github.com/hillu/go-yara/v4
//   3. go build -tags yara   /   go test -tags yara ./...

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	goyara "github.com/hillu/go-yara/v4"
)

// YaraScanner implements Scanner using go-yara and a compiled Rules set.
type YaraScanner struct {
	rules *goyara.Rules
}

func (y *YaraScanner) IsStub() bool { return false }

func (y *YaraScanner) YARAVersion() string { return goyara.Version() }

// Scan runs the compiled YARA rules against data and returns all matches.
// Thread-safe: goyara.Rules.ScanMem may be called concurrently.
func (y *YaraScanner) Scan(data []byte) (ScanResult, error) {
	matches, err := y.rules.ScanMem(data, 0, 0)
	if err != nil {
		return ScanResult{}, err
	}

	var result ScanResult
	for _, m := range matches {
		score := defaultRuleScore
		desc := ""
		author := ""
		for _, meta := range m.Metas {
			switch meta.Identifier {
			case "score":
				switch v := meta.Value.(type) {
				case int:
					score = v
				case int32:
					score = int(v)
				case int64:
					score = int(v)
				}
			case "description":
				if s, ok := meta.Value.(string); ok {
					desc = s
				}
			case "author":
				if s, ok := meta.Value.(string); ok {
					author = s
				}
			}
		}

		var sms []StringMatch
		for _, s := range m.Strings {
			sms = append(sms, StringMatch{
				Identifier: s.Name,
				Offset:     int(s.Offset),
				Data:       s.Data,
			})
		}

		result.Matches = append(result.Matches, Match{
			RuleName:    m.Rule,
			Tags:        m.Tags,
			Score:       score,
			Description: desc,
			Author:      author,
			Strings:     sms,
		})
	}
	return result, nil
}

// NewScanner compiles all *.yar / *.yara files found under rulesDir (recursive).
// Falls back to StubScanner when rulesDir is empty or contains no rule files.
func NewScanner(rulesDir string) (Scanner, error) {
	if rulesDir == "" {
		logStd.Println("[INFO] Scanner: no RULES_DIR configured; running in stub mode")
		return StubScanner{}, nil
	}

	compiler, err := goyara.NewCompiler()
	if err != nil {
		return nil, fmt.Errorf("yara compiler init: %w", err)
	}

	count := 0
	err = filepath.WalkDir(rulesDir, func(path string, d os.DirEntry, werr error) error {
		if werr != nil || d.IsDir() {
			return werr
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yar" && ext != ".yara" {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("open rule %s: %w", path, err)
		}
		defer f.Close()
		// Namespace = basename without extension; keeps rule names unambiguous.
		ns := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if err := compiler.AddFile(f, ns); err != nil {
			return fmt.Errorf("compile %s: %w", path, err)
		}
		count++
		logStd.Printf("[INFO] Loaded YARA rule file: %s (ns=%s)", path, ns)
		return nil
	})
	if err != nil {
		return nil, err
	}

	if count == 0 {
		logStd.Printf("[WARN] No *.yar / *.yara files found in %s; running in stub mode", rulesDir)
		return StubScanner{}, nil
	}

	rules, err := compiler.GetRules()
	if err != nil {
		return nil, fmt.Errorf("finalize rules: %w", err)
	}

	logStd.Printf("[INFO] Scanner: compiled %d YARA rule file(s) from %s (yara %s)", count, rulesDir, goyara.Version())
	return &YaraScanner{rules: rules}, nil
}
