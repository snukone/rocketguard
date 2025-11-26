package main

import (
	"context"
    "bytes"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "testing"
    "time"
	"os"
)

func TestFingerprintUniqueness(t *testing.T) {
	a1 := &rocketguard.Alert{Labels: map[string]string{"alertname":"A","job":"j1","instance":"i1","severity":"critical"}}
	a2 := &rocketguard.Alert{Labels: map[string]string{"alertname":"A","job":"j1","instance":"i1","severity":"critical"}}

	f1 := rocketguard.Fingerprint(a1)
	f2 := rocketguard.Fingerprint(a2)

	if f1 != f2 {
		t.Fatalf("fingerprints must match, got %s vs %s", f1, f2)
	}
}

func TestSetIfNotExistsMemory(t *testing.T) {
	ctx := context.Background()
	rocketguard.UseRedis = false
	rg := rocketguard.InitInMemoryCacheForTests(1) // 1s ttl

	ok, err := rocketguard.SetIfNotExists(ctx, "key1", 1)
	if err != nil || !ok {
		t.Fatalf("expected first insert ok, err=%v", err)
	}

	ok, err = rocketguard.SetIfNotExists(ctx, "key1", 1)
	if err != nil || ok {
		t.Fatalf("expected second insert suppressed, err=%v", err)
	}

	_ = rg
}

func TestLoadReceiverMap(t *testing.T) {
	data := []byte("rocketchat:testurl")
	os.WriteFile("test_receivers.yaml", data, 0644)
	defer os.Remove("test_receivers.yaml")

	_, err := rocketguard.LoadReceiverMap("test_receivers.yaml")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFingerprintStable(t *testing.T) {
    a1 := Alert{Labels: map[string]string{"alertname":"Test","job":"svc","instance":"i1","severity":"warning"}}
    a2 := Alert{Labels: map[string]string{"alertname":"Test","job":"svc","instance":"i1","severity":"warning"}}
    if fingerprint(&a1) != fingerprint(&a2) {
        t.Fatalf("fingerprint should be equal for identical alerts")
    }
}

func TestFingerprintDiff(t *testing.T) {
    a1 := Alert{Labels: map[string]string{"alertname":"A"}}
    a2 := Alert{Labels: map[string]string{"alertname":"B"}}
    if fingerprint(&a1) == fingerprint(&a2) {
        t.Fatalf("fingerprint should differ for different alerts")
    }
}

func TestSetIfNotExistsMemory(t *testing.T) {
    memCache = nil
    useRedis = false
    memCache = nil
    memCache = cache.New(1*time.Second, 1*time.Second)

    ok, err := setIfNotExists(context.Background(), "k1", 1)
    if err != nil || !ok {
        t.Fatalf("expected first insert ok, got err=%v ok=%v", err, ok)
    }

    ok, err = setIfNotExists(context.Background(), "k1", 1)
    if err != nil {
        t.Fatalf("unexpected err: %v", err)
    }
    if ok {
        t.Fatalf("expected second insert to be suppressed")
    }
}

func TestLoadReceiverMap(t *testing.T) {
    yaml := []byte("test: ['http://x']")
    os.WriteFile("/tmp/rcv.yaml", yaml, 0644)
    m, err := loadReceiverMap("/tmp/rcv.yaml")
    if err != nil { t.Fatalf("unexpected err: %v", err) }
    if len(m["test"]) != 1 { t.Fatalf("expected 1 url") }
}

type dummyRoundTripper struct{}
func (d dummyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
    return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewBuffer([]byte("ok")))}, nil
}

func TestWebhookForward(t *testing.T) {
    receiverMap = ReceiverMap{"test": {"http://dummy"}}
    httpCli = &http.Client{Transport: dummyRoundTripper{}}
    memCache = cache.New(cache.NoExpiration, cache.NoExpiration)
    useRedis = false

    payload := AMPayload{Receiver:"test", Alerts: []Alert{{Labels: map[string]string{"alertname":"A"}}}}
    b, _ := json.Marshal(payload)
    req := httptest.NewRequest("POST", "/webhook", bytes.NewReader(b))
    w := httptest.NewRecorder()

    handleWebhook(w, req)
    if w.Code != 200 {
        t.Fatalf("expected 200, got %d", w.Code)
    }
}