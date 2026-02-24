package main

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// logStd is the package-level logger used by scanner files before the Server is
// constructed. The main Server also uses it for runtime messages.
var logStd = log.New(os.Stderr, "", log.LstdFlags)

// ── Config ────────────────────────────────────────────────────────────────────

// Config holds all server configuration. Values are read from CLI flags;
// environment variables are the defaults for each flag.
type Config struct {
	Port          int
	RulesDir      string
	LogFile       string
	UploadsDir    string
	MaxConcurrent int // max simultaneous synchronous scans
	QueueMaxSize  int // max pending async jobs before 503
	RetryAfter    int // value of Retry-After header on 503 responses (seconds)
}

func configFromFlags() Config {
	var c Config
	flag.IntVar(&c.Port, "port", envInt("PORT", 8080), "Listening port")
	flag.StringVar(&c.RulesDir, "rules-dir", envStr("RULES_DIR", "rules"), "Directory with *.yar / *.yara files (recursive)")
	flag.StringVar(&c.LogFile, "log-file", envStr("LOG_FILE", ""), "Path to JSONL audit log (empty = no file log)")
	flag.StringVar(&c.UploadsDir, "uploads-dir", envStr("UPLOADS_DIR", ""), "Directory to persist uploaded samples (empty = discard)")
	flag.IntVar(&c.MaxConcurrent, "max-concurrent", envInt("MAX_CONCURRENT", 4), "Max simultaneous sync scans")
	flag.IntVar(&c.QueueMaxSize, "queue-max-size", envInt("QUEUE_MAX_SIZE", 100), "Max queued async jobs")
	flag.IntVar(&c.RetryAfter, "retry-after", envInt("RETRY_AFTER", 30), "Retry-After seconds sent with 503")
	flag.Parse()
	return c
}

func envInt(key string, def int) int {
	if s := os.Getenv(key); s != "" {
		if v, err := strconv.Atoi(s); err == nil {
			return v
		}
	}
	return def
}

func envStr(key, def string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return def
}

// ── In-memory job store ───────────────────────────────────────────────────────

// Job represents an async scan job.
type Job struct {
	ID      string
	Status  string // queued | running | done | error
	Results []FindingResult
	ErrMsg  string
}

// asyncJob is the work item placed on the queue channel.
type asyncJob struct {
	id         string
	data       []byte
	clientPath string
	source     string
}

// ── HTTP response types ───────────────────────────────────────────────────────

// FindingResult is one element in the JSON array returned by /api/check.
// It matches what thunderstormAPI and the collector expect.
type FindingResult struct {
	Level   string         `json:"level"`
	Module  string         `json:"module"`
	Message string         `json:"message"`
	Score   int            `json:"score"`
	Context FindingContext `json:"context"`
	Matches []MatchEntry   `json:"matches"`
}

// FindingContext holds file metadata attached to a finding.
type FindingContext struct {
	Ext        string `json:"ext"`
	File       string `json:"file"`
	FirstBytes string `json:"firstBytes"`
	MD5        string `json:"md5"`
	SHA1       string `json:"sha1"`
	SHA256     string `json:"sha256"`
	Size       int    `json:"size"`
	Type       string `json:"type"`
}

// MatchEntry is one YARA rule match within a FindingResult.
type MatchEntry struct {
	Matched  []string `json:"matched"`
	Reason   string   `json:"reason"`
	Ref      string   `json:"ref"`
	Ruledate string   `json:"ruledate"`
	Rulename string   `json:"rulename"`
	Subscore int      `json:"subscore"`
	Tags     []string `json:"tags"`
}

// ── JSONL log types ───────────────────────────────────────────────────────────

type logEntry struct {
	Type        string     `json:"type"`
	Meta        logMeta    `json:"meta"`
	Message     string     `json:"message"`
	Subject     logSubject `json:"subject"`
	Score       int        `json:"score"`
	Reasons     []logReason `json:"reasons"`
	ReasonCount int        `json:"reason_count"`
	LogVersion  string     `json:"log_version"`
}

type logMeta struct {
	Time     string `json:"time"`
	Level    string `json:"level"`
	Module   string `json:"module"`
	ScanID   string `json:"scan_id"`
	Hostname string `json:"hostname"`
}

type logSubject struct {
	Type           string        `json:"type"`
	Path           string        `json:"path"`
	ClientFilename string        `json:"client_filename,omitempty"`
	Exists         string        `json:"exists"`
	Extension      string        `json:"extension"`
	Hashes         logHashes     `json:"hashes"`
	FirstBytes     logFirstBytes `json:"first_bytes"`
	Size           int           `json:"size"`
	Source         string        `json:"source"`
}

type logHashes struct {
	SHA256 string `json:"sha256"`
	SHA1   string `json:"sha1"`
	MD5    string `json:"md5"`
}

type logFirstBytes struct {
	Hex   string `json:"hex"`
	ASCII string `json:"ascii"`
}

type logReason struct {
	Type      string       `json:"type"`
	Summary   string       `json:"summary"`
	Signature logSignature `json:"signature"`
	Matched   []logMatched `json:"matched"`
}

type logSignature struct {
	Score       int      `json:"score"`
	Origin      string   `json:"origin"`
	Kind        string   `json:"kind"`
	Tags        []string `json:"tags"`
	RuleName    string   `json:"rule_name"`
	Description string   `json:"description"`
	Author      string   `json:"author"`
}

type logMatched struct {
	Data    logData `json:"data"`
	Context logData `json:"context"`
	Offset  int     `json:"offset"`
	Field   string  `json:"field"`
}

type logData struct {
	Data     string `json:"data"`
	Encoding string `json:"encoding"`
}

// ── Server ────────────────────────────────────────────────────────────────────

// Server holds all runtime state and implements http.Handler via its Mux.
type Server struct {
	cfg      Config
	scanner  Scanner
	hostname string
	mux      *http.ServeMux

	startTime time.Time
	scanned   atomic.Int64

	scanTimesMu sync.Mutex
	scanTimes   []int64 // millisecond durations, ring buffer capped at 1000

	// sem is a buffered channel used as a counting semaphore for sync scans.
	// acquire: sem <- struct{}{} (non-blocking); release: <-sem
	sem chan struct{}

	// queue is a buffered channel of async jobs.
	queue chan *asyncJob

	jobsMu sync.RWMutex
	jobs   map[string]*Job

	logMu   sync.Mutex
	logFile *os.File // nil when no log file is configured
}

// newServer constructs and wires up a Server. It starts the background async
// worker goroutine. Call s.Close() to stop it (the goroutine exits when the
// queue channel is closed, but since it is a daemon-style goroutine it also
// exits when the process does).
func newServer(cfg Config, sc Scanner) (*Server, error) {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "thunderstorm-stub"
	}

	s := &Server{
		cfg:       cfg,
		scanner:   sc,
		hostname:  hostname,
		startTime: time.Now(),
		sem:       make(chan struct{}, cfg.MaxConcurrent),
		queue:     make(chan *asyncJob, cfg.QueueMaxSize),
		jobs:      make(map[string]*Job),
	}

	if cfg.LogFile != "" {
		f, err := os.OpenFile(cfg.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("open log file %s: %w", cfg.LogFile, err)
		}
		s.logFile = f
	}

	if cfg.UploadsDir != "" {
		if err := os.MkdirAll(cfg.UploadsDir, 0755); err != nil {
			return nil, fmt.Errorf("create uploads dir %s: %w", cfg.UploadsDir, err)
		}
	}

	s.mux = s.buildMux()
	go s.asyncWorker()
	return s, nil
}

// ServeHTTP implements http.Handler so *Server can be used directly with httptest.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// buildMux registers all routes.
func (s *Server) buildMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/check", s.handleCheck)
	mux.HandleFunc("/api/checkAsync", s.handleCheckAsync)
	mux.HandleFunc("/api/getAsyncResults", s.handleGetAsyncResults)
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/info", s.handleInfo)
	mux.HandleFunc("/api/collection", s.handleCollection)
	return mux
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// handleCheck is the synchronous scan endpoint (POST /api/check).
// Uses the semaphore to cap concurrency; returns 503 + Retry-After when full.
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Try to acquire semaphore slot (non-blocking).
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	default:
		s.respond503(w)
		return
	}

	data, clientPath, source, err := s.extractUpload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	scanID := newUUID()
	results, err := s.doScan(scanID, data, clientPath, source)
	if err != nil {
		http.Error(w, "scan error: "+err.Error(), http.StatusInternalServerError)
		return
	}

	s.writeJSON(w, results)
}

// handleCheckAsync is the async submission endpoint (POST /api/checkAsync).
// Returns {"id": "<uuid>"} immediately; scanning happens in the background.
func (s *Server) handleCheckAsync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	data, clientPath, source, err := s.extractUpload(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	jobID := newUUID()
	job := &Job{ID: jobID, Status: "queued"}

	s.jobsMu.Lock()
	s.jobs[jobID] = job
	s.jobsMu.Unlock()

	item := &asyncJob{id: jobID, data: data, clientPath: clientPath, source: source}

	select {
	case s.queue <- item:
		// queued successfully
	default:
		// Queue full: roll back the job entry and return 503.
		s.jobsMu.Lock()
		delete(s.jobs, jobID)
		s.jobsMu.Unlock()
		s.respond503(w)
		return
	}

	s.writeJSON(w, map[string]string{"id": jobID})
}

// handleGetAsyncResults polls for an async job result (GET /api/getAsyncResults?id=).
// The "status" key is always present — required by thunderstormAPI.thunderstorm:227.
func (s *Server) handleGetAsyncResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := r.URL.Query().Get("id")
	s.jobsMu.RLock()
	job, ok := s.jobs[id]
	s.jobsMu.RUnlock()

	if !ok {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "error",
			"message": "unknown job id",
		})
		return
	}

	s.jobsMu.RLock()
	status := job.Status
	results := job.Results
	errMsg := job.ErrMsg
	s.jobsMu.RUnlock()

	resp := map[string]interface{}{
		"status":  status,
		"results": results,
	}
	if errMsg != "" {
		resp["message"] = errMsg
	}
	s.writeJSON(w, resp)
}

// handleStatus returns server metrics (GET /api/status).
// "uptime_seconds" is required by thunderstormAPI.thunderstorm:257.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.jobsMu.RLock()
	queued := 0
	for _, j := range s.jobs {
		if j.Status == "queued" {
			queued++
		}
	}
	s.jobsMu.RUnlock()

	s.writeJSON(w, map[string]interface{}{
		"uptime_seconds":             int(time.Since(s.startTime).Seconds()),
		"scanned_samples":            s.scanned.Load(),
		"avg_scan_time_milliseconds": s.avgScanTimeMs(),
		"queued_async_requests":      queued,
	})
}

// handleInfo returns version / mode information (GET /api/info).
// "thor_version" is required by thunderstormAPI tests (test_basic.py:30).
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.writeJSON(w, map[string]interface{}{
		"thor_version":  "10.6.0",
		"yara_version":  s.scanner.YARAVersion(),
		"stub_mode":     s.scanner.IsStub(),
		"rules_dir":     s.cfg.RulesDir,
	})
}

// handleCollection handles POST /api/collection — collection begin/end markers.
// On a "begin" request it generates a scan_id and returns it; on "end" it logs stats.
// This endpoint is optional and forward-compatible: collectors silently ignore 404.
func (s *Server) handleCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	markerType, _ := req["type"].(string)
	source, _ := req["source"].(string)
	collector, _ := req["collector"].(string)

	switch markerType {
	case "begin":
		scanID := fmt.Sprintf("%s", newUUID())
		logStd.Printf("[INFO] Collection begin: source=%s collector=%s scan_id=%s", source, collector, scanID)
		s.writeJSON(w, map[string]interface{}{"scan_id": scanID})
	case "end":
		scanID, _ := req["scan_id"].(string)
		stats, _ := req["stats"].(map[string]interface{})
		logStd.Printf("[INFO] Collection end: source=%s collector=%s scan_id=%s stats=%v", source, collector, scanID, stats)
		s.writeJSON(w, map[string]interface{}{"ok": true})
	default:
		http.Error(w, "unknown marker type", http.StatusBadRequest)
	}
}

// ── Core scan logic ───────────────────────────────────────────────────────────

// doScan runs the scanner, builds the HTTP response slice and writes a JSONL line.
// It is safe to call from multiple goroutines concurrently.
func (s *Server) doScan(scanID string, data []byte, clientPath, source string) ([]FindingResult, error) {
	t0 := time.Now()

	hashes := computeHashes(data)
	ext := filepath.Ext(clientPath)

	sr, err := s.scanner.Scan(data)
	if err != nil {
		// Write an error log entry and propagate.
		s.writeLogEntry(buildErrorLogEntry(scanID, s.hostname, clientPath, source, ext, hashes, data, err))
		return nil, err
	}

	durationMs := time.Since(t0).Milliseconds()
	s.recordScan(durationMs)

	// Determine stored path for JSONL subject.path
	storedPath := clientPath
	if s.cfg.UploadsDir != "" {
		storedPath = filepath.Join(s.cfg.UploadsDir, scanID+ext)
		_ = os.WriteFile(storedPath, data, 0644)
	}

	// Sort matches by RuleName for deterministic output.
	matches := make([]Match, len(sr.Matches))
	copy(matches, sr.Matches)
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].RuleName < matches[j].RuleName
	})

	// Collect sub-scores for accumulation.
	subScores := make([]int, len(matches))
	for i, m := range matches {
		subScores[i] = m.Score
	}
	totalScore := AccumulateScores(subScores)
	level := "Info"
	message := "No match"
	module := "ThunderstormTestServer"

	if len(matches) > 0 {
		level = ScoreToLevel(totalScore, subScores)
		message = "Malicious file found"
		module = "YARA"
	}

	// ── Build HTTP response ──────────────────────────────────────────────────
	var httpResults []FindingResult

	if len(matches) > 0 {
		var matchEntries []MatchEntry
		for _, m := range matches {
			// Sort strings by (offset, identifier) for determinism.
			strs := make([]StringMatch, len(m.Strings))
			copy(strs, m.Strings)
			sort.Slice(strs, func(i, j int) bool {
				if strs[i].Offset != strs[j].Offset {
					return strs[i].Offset < strs[j].Offset
				}
				return strs[i].Identifier < strs[j].Identifier
			})

			var matched []string
			for _, sm := range strs {
				matched = append(matched, fmt.Sprintf("%s: %x", sm.Identifier, sm.Data))
			}
			if matched == nil {
				matched = []string{}
			}
			tags := make([]string, len(m.Tags))
			copy(tags, m.Tags)
			sort.Strings(tags)

			matchEntries = append(matchEntries, MatchEntry{
				Matched:  matched,
				Reason:   fmt.Sprintf("YARA rule %s", m.RuleName),
				Ref:      "",
				Ruledate: "",
				Rulename: m.RuleName,
				Subscore: m.Score,
				Tags:     tags,
			})
		}

		httpResults = []FindingResult{{
			Level:   level,
			Module:  "Filescan",
			Message: message,
			Score:   totalScore,
			Context: FindingContext{
				Ext:        ext,
				File:       clientPath,
				FirstBytes: firstBytesRepr(data),
				MD5:        hashes.MD5,
				SHA1:       hashes.SHA1,
				SHA256:     hashes.SHA256,
				Size:       len(data),
				Type:       "",
			},
			Matches: matchEntries,
		}}
	}

	// ── Build JSONL log entry ────────────────────────────────────────────────
	var reasons []logReason
	for _, m := range matches {
		strs := make([]StringMatch, len(m.Strings))
		copy(strs, m.Strings)
		sort.Slice(strs, func(i, j int) bool {
			if strs[i].Offset != strs[j].Offset {
				return strs[i].Offset < strs[j].Offset
			}
			return strs[i].Identifier < strs[j].Identifier
		})

		var logMatcheds []logMatched
		for _, sm := range strs {
			logMatcheds = append(logMatcheds, logMatched{
				Data:    logData{Data: fmt.Sprintf("%x", sm.Data), Encoding: "plain"},
				Context: logData{Data: "", Encoding: "plain"},
				Offset:  sm.Offset,
				Field:   "/content",
			})
		}
		if logMatcheds == nil {
			logMatcheds = []logMatched{}
		}

		tags := make([]string, len(m.Tags))
		copy(tags, m.Tags)
		sort.Strings(tags)

		reasons = append(reasons, logReason{
			Type:    "reason",
			Summary: fmt.Sprintf("YARA rule %s / %s", m.RuleName, m.Description),
			Signature: logSignature{
				Score:       m.Score,
				Origin:      "custom",
				Kind:        "YARA Rule",
				Tags:        tags,
				RuleName:    m.RuleName,
				Description: m.Description,
				Author:      m.Author,
			},
			Matched: logMatcheds,
		})
	}
	if reasons == nil {
		reasons = []logReason{}
	}

	entry := logEntry{
		Type: "THOR finding",
		Meta: logMeta{
			Time:     time.Now().UTC().Format(time.RFC3339),
			Level:    level,
			Module:   module,
			ScanID:   scanID,
			Hostname: s.hostname,
		},
		Message: message,
		Subject: logSubject{
			Type:           "file",
			Path:           storedPath,
			ClientFilename: clientPath,
			Exists:         "yes",
			Extension:      ext,
			Hashes: logHashes{
				SHA256: hashes.SHA256,
				SHA1:   hashes.SHA1,
				MD5:    hashes.MD5,
			},
			FirstBytes: logFirstBytes{
				Hex:   fmt.Sprintf("%x", firstBytes(data)),
				ASCII: firstBytesASCII(data),
			},
			Size:   len(data),
			Source: source,
		},
		Score:       totalScore,
		Reasons:     reasons,
		ReasonCount: len(reasons),
		LogVersion:  "v3.0.0",
	}
	s.writeLogEntry(entry)

	if httpResults == nil {
		httpResults = []FindingResult{}
	}
	return httpResults, nil
}

// asyncWorker processes jobs from the queue channel in a single goroutine.
// Running a single worker keeps async ordering predictable; the queue provides
// back-pressure (503 when full) rather than unbounded goroutine spawning.
func (s *Server) asyncWorker() {
	for item := range s.queue {
		s.jobsMu.Lock()
		if j, ok := s.jobs[item.id]; ok {
			j.Status = "running"
		}
		s.jobsMu.Unlock()

		results, err := s.doScan(item.id, item.data, item.clientPath, item.source)

		s.jobsMu.Lock()
		if j, ok := s.jobs[item.id]; ok {
			if err != nil {
				j.Status = "error"
				j.ErrMsg = err.Error()
			} else {
				j.Status = "done"
				j.Results = results
			}
		}
		s.jobsMu.Unlock()
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// extractUpload parses the multipart POST and returns the file bytes, the
// client-supplied filename (absolute path from the client), and the source param.
func (s *Server) extractUpload(r *http.Request) (data []byte, clientPath, source string, err error) {
	if err = r.ParseMultipartForm(256 << 20); err != nil {
		return nil, "", "", fmt.Errorf("parse multipart: %w", err)
	}
	f, header, err := r.FormFile("file")
	if err != nil {
		return nil, "", "", fmt.Errorf("missing 'file' field: %w", err)
	}
	defer f.Close()

	data, err = io.ReadAll(f)
	if err != nil {
		return nil, "", "", fmt.Errorf("read file: %w", err)
	}

	source = r.URL.Query().Get("source")
	return data, header.Filename, source, nil
}

type fileHashes struct {
	MD5    string
	SHA1   string
	SHA256 string
}

func computeHashes(data []byte) fileHashes {
	m := md5.Sum(data)
	s1 := sha1.Sum(data)
	s256 := sha256.Sum256(data)
	return fileHashes{
		MD5:    fmt.Sprintf("%x", m),
		SHA1:   fmt.Sprintf("%x", s1),
		SHA256: fmt.Sprintf("%x", s256),
	}
}

func firstBytes(data []byte) []byte {
	n := 16
	if len(data) < n {
		n = len(data)
	}
	return data[:n]
}

func firstBytesASCII(data []byte) string {
	chunk := firstBytes(data)
	var b strings.Builder
	for _, c := range chunk {
		if c >= 32 && c < 127 {
			b.WriteByte(c)
		} else {
			b.WriteByte('.')
		}
	}
	return b.String()
}

// firstBytesRepr returns the "hex / ascii" string used in context.firstBytes.
// Format mirrors THOR: "4d5a9000... / MZ...".
func firstBytesRepr(data []byte) string {
	chunk := firstBytes(data)
	return fmt.Sprintf("%x / %s", chunk, firstBytesASCII(data))
}

func (s *Server) respond503(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Retry-After", strconv.Itoa(s.cfg.RetryAfter))
	w.WriteHeader(http.StatusServiceUnavailable)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": "server overloaded"})
}

func (s *Server) writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		logStd.Printf("[ERROR] JSON encode: %v", err)
	}
}

func (s *Server) writeLogEntry(entry interface{}) {
	if s.logFile == nil {
		return
	}
	line, err := json.Marshal(entry)
	if err != nil {
		logStd.Printf("[ERROR] marshal log entry: %v", err)
		return
	}
	s.logMu.Lock()
	defer s.logMu.Unlock()
	_, _ = s.logFile.Write(append(line, '\n'))
}

func buildErrorLogEntry(scanID, hostname, clientPath, source, ext string, hashes fileHashes, data []byte, scanErr error) logEntry {
	return logEntry{
		Type: "THOR finding",
		Meta: logMeta{
			Time:     time.Now().UTC().Format(time.RFC3339),
			Level:    "Error",
			Module:   "ThunderstormTestServer",
			ScanID:   scanID,
			Hostname: hostname,
		},
		Message: "Scan error",
		Subject: logSubject{
			Type:           "file",
			Path:           clientPath,
			ClientFilename: clientPath,
			Exists:         "yes",
			Extension:      ext,
			Hashes: logHashes{
				SHA256: hashes.SHA256,
				SHA1:   hashes.SHA1,
				MD5:    hashes.MD5,
			},
			FirstBytes: logFirstBytes{
				Hex:   fmt.Sprintf("%x", firstBytes(data)),
				ASCII: firstBytesASCII(data),
			},
			Size:   len(data),
			Source: source,
		},
		Score:       0,
		Reasons:     []logReason{},
		ReasonCount: 0,
		LogVersion:  "v3.0.0",
	}
}

func (s *Server) recordScan(ms int64) {
	s.scanned.Add(1)
	s.scanTimesMu.Lock()
	defer s.scanTimesMu.Unlock()
	s.scanTimes = append(s.scanTimes, ms)
	if len(s.scanTimes) > 1000 {
		s.scanTimes = s.scanTimes[1:]
	}
}

func (s *Server) avgScanTimeMs() int64 {
	s.scanTimesMu.Lock()
	defer s.scanTimesMu.Unlock()
	if len(s.scanTimes) == 0 {
		return 0
	}
	var sum int64
	for _, t := range s.scanTimes {
		sum += t
	}
	return sum / int64(len(s.scanTimes))
}

// newUUID returns a random UUID v4 string using crypto/rand.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// ── Entry point ───────────────────────────────────────────────────────────────

func main() {
	cfg := configFromFlags()

	sc, err := NewScanner(cfg.RulesDir)
	if err != nil {
		logStd.Fatalf("[FATAL] Scanner init: %v", err)
	}

	srv, err := newServer(cfg, sc)
	if err != nil {
		logStd.Fatalf("[FATAL] Server init: %v", err)
	}

	addr := fmt.Sprintf(":%d", cfg.Port)
	logStd.Printf("[INFO] Thunderstorm stub server listening on %s (stub_mode=%v)", addr, sc.IsStub())
	if cfg.LogFile != "" {
		logStd.Printf("[INFO] JSONL log → %s", cfg.LogFile)
	}

	if err := http.ListenAndServe(addr, srv); err != nil {
		logStd.Fatalf("[FATAL] ListenAndServe: %v", err)
	}
}
