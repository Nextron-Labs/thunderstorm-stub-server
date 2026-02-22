package main

// Integration tests for the Thunderstorm stub server.
//
// These tests start a real HTTP server using net/http/httptest and exercise
// exactly the same HTTP contract that thunderstormAPI and thunderstorm-collector
// expect.
//
// Run in stub mode (no YARA):
//   go test ./...
//
// Run with real YARA (requires libyara + go-yara):
//   go test -tags yara ./...

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── Test fixtures ─────────────────────────────────────────────────────────────

var (
	testSrv        *httptest.Server
	testLogFile    string
	testUploadsDir string
	testSamplePath string
	testSampleSHA256 string
)

// TestMain starts one server instance shared by all tests in this package.
// This mirrors what the collector and thunderstormAPI do: point a client at a
// running server and fire requests.
func TestMain(m *testing.M) {
	tmpDir, err := os.MkdirTemp("", "ts-stub-test-*")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(tmpDir)

	testLogFile = filepath.Join(tmpDir, "test.jsonl")
	testUploadsDir = filepath.Join(tmpDir, "uploads")

	// The test sample lives in testdata/; copy it to tmpDir so the absolute
	// path in the multipart filename changes per test run (exercises the
	// client-path round-trip).
	src := filepath.Join("testdata", "samples", "test_sample.bin")
	testSamplePath = filepath.Join(tmpDir, "test_sample.bin")
	sampleData, err := os.ReadFile(src)
	if err != nil {
		panic(fmt.Sprintf("read test sample %s: %v", src, err))
	}
	if err := os.WriteFile(testSamplePath, sampleData, 0644); err != nil {
		panic(err)
	}
	h := computeHashes(sampleData)
	testSampleSHA256 = h.SHA256

	// Build scanner pointing at testdata/rules.
	rulesDir := filepath.Join("testdata", "rules")
	sc, err := NewScanner(rulesDir)
	if err != nil {
		panic(fmt.Sprintf("scanner init: %v", err))
	}

	cfg := Config{
		RulesDir:      rulesDir,
		LogFile:       testLogFile,
		UploadsDir:    testUploadsDir,
		MaxConcurrent: 4,
		QueueMaxSize:  10,
		RetryAfter:    1, // short for tests
	}
	srv, err := newServer(cfg, sc)
	if err != nil {
		panic(fmt.Sprintf("server init: %v", err))
	}

	testSrv = httptest.NewServer(srv)
	defer testSrv.Close()

	// Wait for uptime_seconds to be at least 1 so the /api/status assertion
	// aligns with what thunderstormAPI.test_basic.py expects (uptime > 0).
	time.Sleep(1100 * time.Millisecond)

	os.Exit(m.Run())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// uploadFile performs a multipart POST that exactly mirrors how thunderstormAPI
// and the Go collector upload files:
//   - field name:  "file"
//   - filename:    absolute path of the file (as returned by path.abspath / filepath.Abs)
//   - content-type: application/octet-stream
//   - query param: source=<source>
func uploadFile(t *testing.T, endpoint, filePath, source string) *http.Response {
	t.Helper()

	absPath, err := filepath.Abs(filePath)
	if err != nil {
		t.Fatalf("abs path: %v", err)
	}
	data, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	h := make(textproto.MIMEHeader)
	h.Set("Content-Disposition",
		fmt.Sprintf(`form-data; name="file"; filename="%s"`, absPath))
	h.Set("Content-Type", "application/octet-stream")
	part, err := writer.CreatePart(h)
	if err != nil {
		t.Fatalf("create part: %v", err)
	}
	if _, err := part.Write(data); err != nil {
		t.Fatalf("write part: %v", err)
	}
	writer.Close()

	url := fmt.Sprintf("%s%s?source=%s", testSrv.URL, endpoint, source)
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", writer.FormDataContentType())
	// Mirror the thunderstormAPI User-Agent header.
	req.Header.Set("User-Agent", "THOR Thunderstorm API Client test")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", endpoint, err)
	}
	return resp
}

func getJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	resp, err := http.Get(testSrv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s: status %d", path, resp.StatusCode)
	}
	var m map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		t.Fatalf("decode JSON from %s: %v", path, err)
	}
	return m
}

func decodeBody(t *testing.T, r *http.Response, v interface{}) {
	t.Helper()
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("decode response body: %v\nbody: %s", err, b)
	}
}

// isStubMode returns true when the server was started without real YARA support.
func isStubMode(t *testing.T) bool {
	t.Helper()
	info := getJSON(t, "/api/info")
	sm, _ := info["stub_mode"].(bool)
	return sm
}

// ── Status endpoint ───────────────────────────────────────────────────────────

func TestStatus_RequiredKeys(t *testing.T) {
	status := getJSON(t, "/api/status")
	for _, key := range []string{"uptime_seconds", "scanned_samples", "avg_scan_time_milliseconds", "queued_async_requests"} {
		if _, ok := status[key]; !ok {
			t.Errorf("status response missing key %q", key)
		}
	}
}

func TestStatus_UptimePositive(t *testing.T) {
	status := getJSON(t, "/api/status")
	uptime, _ := status["uptime_seconds"].(float64)
	if uptime <= 0 {
		t.Errorf("uptime_seconds should be > 0, got %v", uptime)
	}
}

func TestStatus_ScannedCountIncrementsAfterSync(t *testing.T) {
	before := getJSON(t, "/api/status")
	resp := uploadFile(t, "/api/check", testSamplePath, "test-host")
	resp.Body.Close()
	after := getJSON(t, "/api/status")

	beforeCount, _ := before["scanned_samples"].(float64)
	afterCount, _ := after["scanned_samples"].(float64)
	if afterCount <= beforeCount {
		t.Errorf("scanned_samples did not increment: before=%v after=%v", beforeCount, afterCount)
	}
}

// ── Info endpoint ─────────────────────────────────────────────────────────────

func TestInfo_ThorVersion(t *testing.T) {
	info := getJSON(t, "/api/info")
	v, ok := info["thor_version"].(string)
	if !ok || v == "" {
		t.Errorf("thor_version missing or empty: %v", info["thor_version"])
	}
}

func TestInfo_YaraVersion(t *testing.T) {
	info := getJSON(t, "/api/info")
	if _, ok := info["yara_version"]; !ok {
		t.Error("yara_version missing from /api/info")
	}
}

// ── Sync endpoint ─────────────────────────────────────────────────────────────

func TestSync_CleanFile_ReturnsEmptyList(t *testing.T) {
	// Create a file that contains no matching strings.
	tmp, _ := os.CreateTemp("", "clean-*.bin")
	tmp.Write(bytes.Repeat([]byte{0x00}, 64))
	tmp.Close()
	defer os.Remove(tmp.Name())

	resp := uploadFile(t, "/api/check", tmp.Name(), "test-host")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var results []interface{}
	decodeBody(t, resp, &results)
	if len(results) != 0 {
		t.Errorf("expected empty result list for clean file, got %d items", len(results))
	}
}

func TestSync_SampleFile_ResponseShape(t *testing.T) {
	resp := uploadFile(t, "/api/check", testSamplePath, "test-host")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var results []map[string]interface{}
	decodeBody(t, resp, &results)

	if isStubMode(t) {
		// Stub mode always returns no matches.
		if len(results) != 0 {
			t.Errorf("stub mode: expected [] but got %d results", len(results))
		}
		return
	}

	// YARA mode: expect at least one finding.
	if len(results) == 0 {
		t.Fatal("expected at least one result for matching sample, got []")
	}

	r := results[0]
	for _, key := range []string{"level", "module", "message", "score", "context", "matches"} {
		if _, ok := r[key]; !ok {
			t.Errorf("result missing key %q", key)
		}
	}

	ctx, _ := r["context"].(map[string]interface{})
	for _, key := range []string{"ext", "file", "firstBytes", "md5", "sha1", "sha256", "size"} {
		if _, ok := ctx[key]; !ok {
			t.Errorf("context missing key %q", key)
		}
	}
}

// TestSync_FullRoundtrip is the key integration test:
// uploads the known sample, verifies the YARA rule fired with the right name
// and that the sha256 in the response matches the actual file hash.
func TestSync_FullRoundtrip(t *testing.T) {
	if isStubMode(t) {
		t.Skip("full roundtrip requires YARA support (-tags yara)")
	}

	resp := uploadFile(t, "/api/check", testSamplePath, "test-host")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var results []map[string]interface{}
	decodeBody(t, resp, &results)

	if len(results) == 0 {
		t.Fatal("expected match for test sample, got empty result")
	}

	// Verify sha256 in context matches the actual file.
	ctx, _ := results[0]["context"].(map[string]interface{})
	if sha256, _ := ctx["sha256"].(string); sha256 != testSampleSHA256 {
		t.Errorf("context.sha256 = %q, want %q", sha256, testSampleSHA256)
	}

	// Verify rule name in matches.
	matches, _ := results[0]["matches"].([]interface{})
	if len(matches) == 0 {
		t.Fatal("expected at least one match entry")
	}
	m0, _ := matches[0].(map[string]interface{})
	if rulename, _ := m0["rulename"].(string); rulename != "TestRule" {
		t.Errorf("rulename = %q, want %q", rulename, "TestRule")
	}

	// Verify level is Alert (score 90 > 80, subscore 90 > 75).
	if level, _ := results[0]["level"].(string); level != "Alert" {
		t.Errorf("level = %q, want \"Alert\"", level)
	}
}

func TestSync_DeterministicOutput(t *testing.T) {
	if isStubMode(t) {
		t.Skip("determinism test requires YARA")
	}

	get := func() []map[string]interface{} {
		resp := uploadFile(t, "/api/check", testSamplePath, "")
		defer resp.Body.Close()
		var results []map[string]interface{}
		decodeBody(t, resp, &results)
		return results
	}

	r1 := get()
	r2 := get()

	if len(r1) != len(r2) {
		t.Fatalf("result lengths differ: %d vs %d", len(r1), len(r2))
	}
	if len(r1) > 0 {
		m1, _ := r1[0]["matches"].([]interface{})
		m2, _ := r2[0]["matches"].([]interface{})
		if len(m1) != len(m2) {
			t.Errorf("match counts differ: %d vs %d", len(m1), len(m2))
		}
		for i := range m1 {
			e1, _ := m1[i].(map[string]interface{})
			e2, _ := m2[i].(map[string]interface{})
			if e1["rulename"] != e2["rulename"] {
				t.Errorf("match[%d] rulename: %v vs %v", i, e1["rulename"], e2["rulename"])
			}
		}
	}
}

// ── 503 overload behaviour ────────────────────────────────────────────────────

func TestSync_503WhenOverloaded(t *testing.T) {
	// Build a tiny server with MaxConcurrent=1 and a slow scanner to guarantee
	// the semaphore fills up during concurrent requests.
	logFile := filepath.Join(t.TempDir(), "overload.jsonl")
	slowSc := &slowScanner{delay: 200 * time.Millisecond}
	cfg := Config{
		MaxConcurrent: 1,
		QueueMaxSize:  10,
		RetryAfter:    1,
		LogFile:       logFile,
	}
	srv, err := newServer(cfg, slowSc)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv)
	defer ts.Close()

	// Write a small temp file.
	tmp, _ := os.CreateTemp("", "503test-*.bin")
	tmp.Write([]byte("hello"))
	tmp.Close()
	defer os.Remove(tmp.Name())

	// Fire 3 concurrent requests; with MaxConcurrent=1 at least 2 must see 503.
	type result struct{ code int }
	ch := make(chan result, 3)
	for i := 0; i < 3; i++ {
		go func() {
			abs, _ := filepath.Abs(tmp.Name())
			data, _ := os.ReadFile(tmp.Name())
			body := &bytes.Buffer{}
			w := multipart.NewWriter(body)
			h := make(textproto.MIMEHeader)
			h.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename="%s"`, abs))
			h.Set("Content-Type", "application/octet-stream")
			p, _ := w.CreatePart(h)
			p.Write(data)
			w.Close()
			req, _ := http.NewRequest("POST", ts.URL+"/api/check?source=test", body)
			req.Header.Set("Content-Type", w.FormDataContentType())
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				ch <- result{-1}
				return
			}
			resp.Body.Close()
			ch <- result{resp.StatusCode}
		}()
	}

	var codes []int
	for i := 0; i < 3; i++ {
		r := <-ch
		codes = append(codes, r.code)
	}

	got503 := false
	for _, c := range codes {
		if c != 200 && c != 503 {
			t.Errorf("unexpected status code %d (want 200 or 503)", c)
		}
		if c == 503 {
			got503 = true
		}
	}
	if !got503 {
		t.Errorf("expected at least one 503 with MaxConcurrent=1, codes=%v", codes)
	}
}

// slowScanner simulates a scan that takes some time, enabling the 503 test.
type slowScanner struct {
	delay time.Duration
}

func (s *slowScanner) Scan(_ []byte) (ScanResult, error) {
	time.Sleep(s.delay)
	return ScanResult{StubMode: true}, nil
}
func (s *slowScanner) IsStub() bool        { return true }
func (s *slowScanner) YARAVersion() string { return "slow-stub" }

// ── Async endpoint ────────────────────────────────────────────────────────────

func TestAsync_SubmitReturnsID(t *testing.T) {
	resp := uploadFile(t, "/api/checkAsync", testSamplePath, "test-host")
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	decodeBody(t, resp, &body)
	if id, ok := body["id"]; !ok || id == "" {
		t.Errorf("expected non-empty 'id' in async response, got %v", body)
	}
}

func TestAsync_PollHasStatusKey(t *testing.T) {
	resp := uploadFile(t, "/api/checkAsync", testSamplePath, "test-host")
	var submit map[string]string
	decodeBody(t, resp, &submit)

	pollResp, err := http.Get(fmt.Sprintf("%s/api/getAsyncResults?id=%s", testSrv.URL, submit["id"]))
	if err != nil {
		t.Fatalf("poll GET: %v", err)
	}
	defer pollResp.Body.Close()
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 from poll, got %d", pollResp.StatusCode)
	}

	var result map[string]interface{}
	decodeBody(t, pollResp, &result)
	if _, ok := result["status"]; !ok {
		t.Errorf("poll response missing 'status' key: %v", result)
	}
}

func TestAsync_EventuallyDone(t *testing.T) {
	resp := uploadFile(t, "/api/checkAsync", testSamplePath, "test-host")
	var submit map[string]string
	decodeBody(t, resp, &submit)
	id := submit["id"]

	deadline := time.Now().Add(10 * time.Second)
	var finalStatus string
	for time.Now().Before(deadline) {
		pollResp, err := http.Get(fmt.Sprintf("%s/api/getAsyncResults?id=%s", testSrv.URL, id))
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		var result map[string]interface{}
		decodeBody(t, pollResp, &result)
		finalStatus, _ = result["status"].(string)
		if finalStatus == "done" || finalStatus == "error" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if finalStatus != "done" {
		t.Errorf("async job did not reach 'done' within 10s; last status=%q", finalStatus)
	}
}

// TestAsync_FullRoundtrip: submit async, poll to done, verify YARA result.
func TestAsync_FullRoundtrip(t *testing.T) {
	if isStubMode(t) {
		t.Skip("async full roundtrip requires YARA support (-tags yara)")
	}

	resp := uploadFile(t, "/api/checkAsync", testSamplePath, "test-source")
	var submit map[string]string
	decodeBody(t, resp, &submit)
	id := submit["id"]

	deadline := time.Now().Add(10 * time.Second)
	var finalResult map[string]interface{}
	for time.Now().Before(deadline) {
		pollResp, err := http.Get(fmt.Sprintf("%s/api/getAsyncResults?id=%s", testSrv.URL, id))
		if err != nil {
			t.Fatalf("poll: %v", err)
		}
		decodeBody(t, pollResp, &finalResult)
		if s, _ := finalResult["status"].(string); s == "done" || s == "error" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if s, _ := finalResult["status"].(string); s != "done" {
		t.Fatalf("job did not reach done; status=%q", s)
	}

	results, _ := finalResult["results"].([]interface{})
	if len(results) == 0 {
		t.Fatal("expected match results in async done response")
	}

	r0, _ := results[0].(map[string]interface{})
	ctx, _ := r0["context"].(map[string]interface{})
	if sha, _ := ctx["sha256"].(string); sha != testSampleSHA256 {
		t.Errorf("sha256 = %q, want %q", sha, testSampleSHA256)
	}

	matches, _ := r0["matches"].([]interface{})
	if len(matches) == 0 {
		t.Fatal("expected at least one match")
	}
	m0, _ := matches[0].(map[string]interface{})
	if rulename, _ := m0["rulename"].(string); rulename != "TestRule" {
		t.Errorf("rulename = %q, want %q", rulename, "TestRule")
	}
}

func TestAsync_UnknownIDReturns404(t *testing.T) {
	resp, err := http.Get(testSrv.URL + "/api/getAsyncResults?id=no-such-id")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("expected 404 for unknown id, got %d", resp.StatusCode)
	}
}

// ── JSONL log ─────────────────────────────────────────────────────────────────

func TestJSONL_LogWrittenAfterScan(t *testing.T) {
	// Reset by noting the current line count first.
	before := countLogLines(t)

	resp := uploadFile(t, "/api/check", testSamplePath, "log-test-source")
	resp.Body.Close()

	after := countLogLines(t)
	if after <= before {
		t.Errorf("expected new JSONL line after scan: before=%d after=%d", before, after)
	}
}

func TestJSONL_SchemaValid(t *testing.T) {
	// Upload and then check the last log line has the required schema.
	resp := uploadFile(t, "/api/check", testSamplePath, "schema-check-source")
	resp.Body.Close()

	entry := lastLogEntry(t)

	if entry["type"] != "THOR finding" {
		t.Errorf("type = %q, want \"THOR finding\"", entry["type"])
	}
	if entry["log_version"] != "v3.0.0" {
		t.Errorf("log_version = %q, want \"v3.0.0\"", entry["log_version"])
	}

	for _, key := range []string{"meta", "message", "subject", "score", "reasons", "reason_count"} {
		if _, ok := entry[key]; !ok {
			t.Errorf("log entry missing key %q", key)
		}
	}

	meta, _ := entry["meta"].(map[string]interface{})
	for _, key := range []string{"time", "level", "module", "scan_id", "hostname"} {
		if _, ok := meta[key]; !ok {
			t.Errorf("meta missing key %q", key)
		}
	}

	subj, _ := entry["subject"].(map[string]interface{})
	for _, key := range []string{"type", "path", "exists", "extension", "hashes", "first_bytes", "size", "source"} {
		if _, ok := subj[key]; !ok {
			t.Errorf("subject missing key %q", key)
		}
	}

	hashes, _ := subj["hashes"].(map[string]interface{})
	if _, ok := hashes["sha256"]; !ok {
		t.Error("subject.hashes missing sha256")
	}

	// Source should be echoed from the query param.
	if subj["source"] != "schema-check-source" {
		t.Errorf("source = %v, want \"schema-check-source\"", subj["source"])
	}
}

// TestJSONL_FullRoundtrip: the key validation — log entry contains the expected
// rule_name and sha256 after scanning the test sample.
func TestJSONL_FullRoundtrip(t *testing.T) {
	if isStubMode(t) {
		t.Skip("JSONL full roundtrip requires YARA support (-tags yara)")
	}

	resp := uploadFile(t, "/api/check", testSamplePath, "jsonl-roundtrip")
	resp.Body.Close()

	entry := lastLogEntry(t)

	subj, _ := entry["subject"].(map[string]interface{})
	hashes, _ := subj["hashes"].(map[string]interface{})
	if sha, _ := hashes["sha256"].(string); sha != testSampleSHA256 {
		t.Errorf("log sha256 = %q, want %q", sha, testSampleSHA256)
	}

	reasons, _ := entry["reasons"].([]interface{})
	if len(reasons) == 0 {
		t.Fatal("expected at least one reason in log entry")
	}
	r0, _ := reasons[0].(map[string]interface{})
	sig, _ := r0["signature"].(map[string]interface{})
	if ruleName, _ := sig["rule_name"].(string); ruleName != "TestRule" {
		t.Errorf("reason.signature.rule_name = %q, want \"TestRule\"", ruleName)
	}
}

// ── Log helpers ───────────────────────────────────────────────────────────────

func countLogLines(t *testing.T) int {
	t.Helper()
	data, err := os.ReadFile(testLogFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("read log: %v", err)
	}
	count := 0
	for _, line := range bytes.Split(data, []byte("\n")) {
		if len(bytes.TrimSpace(line)) > 0 {
			count++
		}
	}
	return count
}

func lastLogEntry(t *testing.T) map[string]interface{} {
	t.Helper()
	data, err := os.ReadFile(testLogFile)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	lines := bytes.Split(data, []byte("\n"))
	for i := len(lines) - 1; i >= 0; i-- {
		line := bytes.TrimSpace(lines[i])
		if len(line) == 0 {
			continue
		}
		var m map[string]interface{}
		if err := json.Unmarshal(line, &m); err != nil {
			t.Fatalf("parse last log line: %v\nline: %s", err, line)
		}
		return m
	}
	t.Fatal("log file is empty")
	return nil
}
