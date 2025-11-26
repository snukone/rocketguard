package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/go-redis/redis/v8"
	"github.com/patrickmn/go-cache"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/yaml.v3"
)

// Config: mapping receivers -> list of target webhook URLs
type ReceiverMap map[string][]string

// Env-config
var (
	portEnv             = envOr("PORT", "8080")
	dedupTTLEnv         = envOr("DEDUP_TTL_SECONDS", "600")
	forwardTimeoutMsEnv = envOr("FORWARD_TIMEOUT_MS", "5000")
	receiverMapPath     = envOr("RECEIVER_MAP_PATH", "/config/receivers.yaml")
	fallbackReceiver    = envOr("FALLBACK_RECEIVER", "")
	logLevelEnv         = envOr("LOG_LEVEL", "info")
	redisURLEnv         = os.Getenv("REDIS_URL")
)

// Prometheus metrics
var (
	forwarded = prometheus.NewCounter(prometheus.CounterOpts{Name: "rocketguard_forwarded_total", Help: "Forwarded alerts"})
	suppressed = prometheus.NewCounter(prometheus.CounterOpts{Name: "rocketguard_suppressed_total", Help: "Suppressed alerts"})
	forwardErr = prometheus.NewCounter(prometheus.CounterOpts{Name: "rocketguard_forward_errors_total", Help: "Forward errors"})
	cacheType  = prometheus.NewGauge(prometheus.GaugeOpts{Name: "rocketguard_cache_type", Help: "0=in-memory,1=redis"})
)

// Alert payloads
type AMPayload struct {
	Receiver string  `json:"receiver"`
	Alerts   []Alert `json:"alerts"`
}

type Alert struct {
	Status       string            `json:"status,omitempty"`
	Labels       map[string]string `json:"labels,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
	StartsAt     string            `json:"startsAt,omitempty"`
	EndsAt       string            `json:"endsAt,omitempty"`
	GeneratorURL string            `json:"generatorURL,omitempty"`
}

// Cache/backends
var (
	memCache *cache.Cache
	rdb      *redis.Client
	useRedis bool
	httpCli  *http.Client
	dedupTTL int

	// receiver map + lock for reload
	receiverMap     = make(ReceiverMap)
	receiverMapLock sync.RWMutex
)

func envOr(k, d string) string {
	v := os.Getenv(k)
	if v == "" {
		return d
	}
	return v
}

func init() {
	prometheus.MustRegister(forwarded, suppressed, forwardErr, cacheType)
}

func parseTTL() time.Duration {
	d, err := time.ParseDuration(dedupTTLEnv + "s")
	if err != nil {
		log.Printf("invalid DEDUP_TTL_SECONDS=%s, defaulting to 600s", dedupTTLEnv)
		return 600 * time.Second
	}
	return d
}

func initCache(ctx context.Context) {
	ttl := parseTTL()
	dedupTTL = int(ttl.Seconds())

	if redisURLEnv != "" {
		opt, err := redis.ParseURL(redisURLEnv)
		if err != nil {
			log.Fatalf("invalid REDIS_URL: %v", err)
		}
		rdb = redis.NewClient(opt)
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Fatalf("redis ping failed: %v", err)
		}
		useRedis = true
		cacheType.Set(1)
		log.Printf("Using Redis cache, TTL=%ds", int(ttl.Seconds()))
		return
	}

	memCache = cache.New(ttl, 1*time.Minute)
	useRedis = false
	cacheType.Set(0)
	log.Printf("Using in-memory cache (not shared), TTL=%ds", int(ttl.Seconds()))
}

func fingerprint(a *Alert) string {
	lbl := a.Labels
	parts := []string{
		lbl["alertname"],
		lbl["job"],
		lbl["instance"],
		lbl["severity"],
		// omit startsAt to allow dedupe of repeated firings
	}
	h := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(h[:])
}

func setIfNotExists(ctx context.Context, key string, ttlSec int) (bool, error) {
	if useRedis {
		ok, err := rdb.SetNX(ctx, key, "1", time.Duration(ttlSec)*time.Second).Result()
		return ok, err
	}
	if memCache == nil {
		return false, fmt.Errorf("in-memory cache not initialized")
	}
	if _, found := memCache.Get(key); found {
		return false, nil
	}
	memCache.Set(key, true, time.Duration(ttlSec)*time.Second)
	return true, nil
}

// load receiver map from yaml file (simple mapping: receiver: [url1, url2])
func loadReceiverMap(path string) (ReceiverMap, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	m := make(map[string][]string)
	if err := yaml.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// watch receiver map file for changes and reload it
func watchReceiverMap(path string) {
	w, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("fsnotify.NewWatcher error: %v", err)
		return
	}
	defer w.Close()
	if err := w.Add(path); err != nil {
		log.Printf("watch add error: %v", err)
		return
	}
	for {
		select {
		case ev, ok := <-w.Events:
			if !ok { return }
			if ev.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
				log.Printf("receiver map changed, reloading...")
				if m, err := loadReceiverMap(path); err == nil {
					receiverMapLock.Lock()
					receiverMap = m
					receiverMapLock.Unlock()
					log.Printf("receiver map reloaded, %d receivers", len(m))
				} else {
					log.Printf("failed to reload receiver map: %v", err)
				}
			}
		case err, ok := <-w.Errors:
			if !ok { return }
			log.Printf("watcher error: %v", err)
		}
	}
}

func getTargetsForReceiver(receiver string) ([]string, error) {
	receiverMapLock.RLock()
	defer receiverMapLock.RUnlock()
	if targets, ok := receiverMap[receiver]; ok && len(targets) > 0 {
		return targets, nil
	}
	if fallbackReceiver != "" {
		if targets, ok := receiverMap[fallbackReceiver]; ok && len(targets) > 0 {
			return targets, nil
		}
	}
	return nil, fmt.Errorf("no targets for receiver %s", receiver)
}

// fan-out forward raw bytes (Alertmanager JSON) to all targets for receiver; returns error if all fail
func forwardToTargets(raw []byte, targets []string) error {
	var lastErr error
	for _, t := range targets {
		if logLevelEnv == "debug" {
            log.Printf("forwarding to %s with raw body:\n%s", t, string(raw))
        }
		req, err := http.NewRequest(http.MethodPost, t, strings.NewReader(string(raw)))
		if err != nil { 
			lastErr = err; 
			if logLevelEnv == "debug" {
				log.Printf("failed to create request for %s: %w", t, err);
			}
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := httpCli.Do(req)
		if err != nil { 
			lastErr = err;
			if logLevelEnv == "debug" {
				log.Printf("forward request to %s failed: %w", t, err);
			}
			continue
		}
		io.Copy(ioutil.Discard, resp.Body)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// success for this target
			return nil
		}
		lastErr = fmt.Errorf("forward target %s returned %d: %s", t, resp.StatusCode, string(body))
	}
	return lastErr
}

func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost { http.Error(w, "only POST", http.StatusMethodNotAllowed); return }

	// read raw body bytes so we can forward a preserved Alertmanager payload
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read error", http.StatusBadRequest)
		return
	}

	var orig AMPayload
	if err := json.Unmarshal(bodyBytes, &orig); err != nil {
		// if we can't parse the Alertmanager JSON, still try to forward raw (fail-fast)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	alerts := orig.Alerts
	if len(alerts) == 0 { w.WriteHeader(200); w.Write([]byte(`{"status":"no_alerts"}`)); return }

	// determine targets based on receiver field
	receiver := orig.Receiver
	targets, err := getTargetsForReceiver(receiver)
	if err != nil {
		log.Printf("no targets for receiver %s: %v", receiver, err)
		http.Error(w, "no target for receiver", http.StatusBadRequest)
		return
	}

	ctx := r.Context()
	toForward := make([]Alert, 0, len(alerts))
	suppressedCount := 0
	for i := range alerts {
		a := &alerts[i]
		key := fingerprint(a)
		ok, err := setIfNotExists(ctx, key, dedupTTL)
		if err != nil {
			// fail-open
			log.Printf("cache error, fail-open: %v", err)
			toForward = append(toForward, *a)
			continue
		}
		if ok { toForward = append(toForward, *a) } else { suppressedCount++ }
	}

	if len(toForward) == 0 {
		suppressed.Add(float64(suppressedCount))
		w.WriteHeader(200)
		json.NewEncoder(w).Encode(map[string]interface{}{"status":"suppressed", "suppressed": suppressedCount})
		return
	}

	// build an Alertmanager-style payload that contains only the forwarded alerts
	out := orig
	out.Alerts = toForward
	outBytes, err := json.Marshal(out)
	if err != nil {
		log.Printf("marshal out error: %v", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	if logLevelEnv == "debug" {
		log.Printf("forwarding minimized alert payload:\n%s", string(outBytes))
	}

	if err := forwardToTargets(outBytes, targets); err != nil {
		forwardErr.Inc()
		log.Printf("forward failed: %v", err)
		http.Error(w, "forward_error", http.StatusBadGateway)
		return
	}

	forwarded.Add(float64(len(toForward)))
	if suppressedCount > 0 { suppressed.Add(float64(suppressedCount)) }
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(map[string]interface{}{"status":"forwarded", "forwarded": len(toForward), "suppressed": suppressedCount})
}

func main() {
	flag.Parse()
	if receiverMapPath == "" { log.Fatalf("RECEIVER_MAP_PATH must be set") }
	if dedupTTLEnv == "" { dedupTTLEnv = "600" }
	if forwardTimeoutMsEnv == "" { forwardTimeoutMsEnv = "5000" }

	// http client
	to, _ := time.ParseDuration(forwardTimeoutMsEnv + "ms")
	httpCli = &http.Client{Timeout: to, Transport: &http.Transport{DialContext: (&net.Dialer{Timeout: 5 * time.Second}).DialContext}}

	ctx := context.Background()
	initCache(ctx)

	// load initial receiver map
	m, err := loadReceiverMap(receiverMapPath)
	if err != nil {
		log.Fatalf("failed to load receiver map: %v", err)
	}
	receiverMapLock.Lock()
	receiverMap = m
	receiverMapLock.Unlock()
	log.Printf("loaded receiver map (%d receivers)", len(m))

	// watch config for changes
	go watchReceiverMap(receiverMapPath)

	http.HandleFunc("/webhook", handleWebhook)
	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200); w.Write([]byte("ok")) })
	http.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		if useRedis && rdb == nil { http.Error(w, "redis-not-ready", http.StatusServiceUnavailable); return }
		w.WriteHeader(200); w.Write([]byte("ready"))
	})
	http.Handle("/metrics", promhttp.Handler())

	addr := ":" + portEnv
	log.Printf("rocketguard starting on %s (TTL=%ds)", addr, dedupTTL)
	if err := http.ListenAndServe(addr, nil); err != nil { log.Fatalf("server failed: %v", err) }
}


// Test helpers for unit tests

// InitInMemoryCacheForTests initialises the in-memory cache for tests with the given TTL in seconds.
// Call this from tests to prepare the cache environment.
func InitInMemoryCacheForTests(ttlSeconds int) {
	memCache = cache.New(time.Duration(ttlSeconds)*time.Second, 1*time.Second)
	useRedis = false
	dedupTTL = ttlSeconds
}

// ResetCache clears cache and redis client for clean test setup.
func ResetCache() {
	memCache = nil
	rdb = nil
	useRedis = false
	dedupTTL = 0
}