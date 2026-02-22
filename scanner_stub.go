//go:build !yara

package main

// NewScanner returns a StubScanner that always reports no matches.
// rulesDir is ignored when YARA support is not compiled in.
// Build with -tags yara to enable real YARA scanning.
func NewScanner(rulesDir string) (Scanner, error) {
	if rulesDir != "" {
		logStd.Printf("[WARN] RULES_DIR set to %q but server was built without -tags yara; running in stub mode", rulesDir)
	}
	logStd.Println("[INFO] Scanner: stub mode (no YARA support compiled in)")
	return StubScanner{}, nil
}
