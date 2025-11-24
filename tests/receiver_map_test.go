package tests

import (
	"github.com/snukone/rocketguard/cmd/rocketguard"
	"os"
	"testing"
)

func TestLoadReceiverMap(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "receivers-*.yaml")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmpfile.Name())

	yamlContent := `
rocketchat-critical:
  - https://example.com/hook1
  - https://example.com/hook2
rocketchat-warning:
  - https://example.com/warn
`
	if _, err := tmpfile.Write([]byte(yamlContent)); err != nil {
		t.Fatalf("failed to write yaml: %v", err)
	}

	m, err := loadReceiverMap(tmpfile.Name())
	if err != nil {
		t.Fatalf("loadReceiverMap returned error: %v", err)
	}

	if len(m) != 2 {
		t.Fatalf("expected 2 receivers, got %d", len(m))
	}

	if len(m["rocketchat-critical"]) != 2 {
		t.Fatalf("expected 2 urls for rocketchat-critical, got %d", len(m["rocketchat-critical"]))
	}

	if m["rocketchat-warning"][0] != "https://example.com/warn" {
		t.Fatalf("unexpected warn url: %s", m["rocketchat-warning"][0])
	}
}
